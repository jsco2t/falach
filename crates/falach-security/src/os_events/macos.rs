//! `IoKitSource` — macOS screen-lock / sleep [`OsLockEventSource`].
//!
//! Observes two OS-level events and forwards each as a
//! `SecurityEvent::OsLock`:
//!
//! - **System sleep** → `OsLock { reason: Sleep }`. Observed via
//!   `NSWorkspace`'s notification center
//!   (`NSWorkspaceWillSleepNotification`).
//! - **Screen lock** → `OsLock { reason: Screensaver }`. Observed via
//!   the distributed notification center
//!   (`com.apple.screenIsLocked`).
//!
//! ## Deviations from the task acceptance criteria
//!
//! Task T5.2's acceptance criteria were written before the macOS APIs
//! were pinned (see the task doc's Technical Notes #1, "confirm at
//! kickoff", and feature design §7 Open Item #7). Two deviations,
//! both anticipated by the task:
//!
//! 1. **Sleep: `NSWorkspace` instead of raw `IOKit`
//!    `IORegisterForSystemPower`.** The AC named the low-level `IOKit`
//!    power-notification API. That API exists to let a process *delay*
//!    sleep (it must call `IOAllowPowerChange` to acknowledge); we
//!    only need to *observe* the sleep edge, for which
//!    `NSWorkspaceWillSleepNotification` is the documented, public,
//!    higher-level equivalent. Choosing it avoids hand-declaring the
//!    `IOKit` C symbols (`objc2-io-kit` is not in the vendored tree) and
//!    keeps the crate's `unsafe` surface to the minimum the trait
//!    demands — consistent with the project's "minimise unsafe / no
//!    hand-rolled FFI" posture. The task's `IOKit` primer explicitly
//!    sanctions this fallback ("if the wrappers are insufficient…",
//!    and conversely if they suffice, use them).
//!
//! 2. **Screen lock: `com.apple.screenIsLocked` instead of
//!    `NSWorkspaceScreensaverDidStartNotification`.** The latter is not
//!    a public symbol — no `NSWorkspace` notification reports screen
//!    *lock* (only screen *sleep*, `NSWorkspaceScreensDidSleep…`). The
//!    distributed notification `com.apple.screenIsLocked` has been the
//!    de facto screen-lock signal across macOS releases and is the
//!    security-relevant edge (the user walked away and locked).
//!
//! ### Known fragility
//!
//! `com.apple.screenIsLocked` is a *private* distributed notification
//! (no public header). It has historically had reliability quirks
//! around fast user switching and lock-from-menu vs. hot-corner across
//! macOS versions. Adequate for this best-effort, MVP-tier signal;
//! tracked as a follow-up so a future "screen-lock unreliable on macOS
//! N" report has a home. Separately, notification delivery is bound to
//! the run loop of the thread that registered the observer; this
//! source registers and runs that loop on its own dedicated thread
//! (per the `attach_event_source` model). If a future macOS release
//! requires main-thread delivery for `NSWorkspace` notifications, the
//! sleep edge would need to move to the main run loop — noted as a
//! follow-up.
//!
//! ## Cargo feature gate
//!
//! Compiled only when `falach-security/iokit` is enabled. The feature
//! is **default-off** so a plain `cargo build` on macOS does not pull
//! the `objc2` framework deps as direct edges or compile this FFI
//! module. Consumers (the TUI / CLI / agent crates) opt in.
//!
//! ## `unsafe` posture
//!
//! This is the crate's only `unsafe`-bearing production module. The
//! crate is `#![cfg_attr(not(test), deny(unsafe_code))]`; this module
//! carries a leading `#![allow(unsafe_code)]`. The pattern mirrors the
//! one `falach-core` reserves for its future `mlock` block (design
//! §3.12). Every `unsafe` call here is an `objc2` FFI call into a
//! framework method or an `extern` static; none manipulates raw memory
//! we own. Audited 2026-05-27.
//!
//! ## Shutdown (Phase 5 T5.0 contract)
//!
//! `IoKitSource` holds a shared `AtomicBool`. The [`ShutdownHandle`]
//! returned by [`OsLockEventSource::shutdown_handle`] sets it. The run
//! loop pumps `CFRunLoopRunInMode` in bounded slices
//! ([`RUN_LOOP_TICK_SECONDS`]) and checks the flag between slices, so
//! `run` returns `Ok(())` within one slice of the signal. Before
//! returning it deregisters both observers, releasing the notification
//! centers' references to the observer object (no leak). Setting an
//! `AtomicBool` does not itself wake a blocked `CFRunLoopRunInMode`,
//! hence the bounded slice rather than `CFRunLoopStop` — the latter
//! would require sharing the non-`Send` `CFRunLoopRef` back to the
//! handle, which is created before `run` spawns the thread.

#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use objc2::rc::{autoreleasepool, Retained};
use objc2::runtime::AnyObject;
use objc2::{define_class, msg_send, sel, AnyThread, DefinedClass};
use objc2_app_kit::{NSWorkspace, NSWorkspaceWillSleepNotification};
use objc2_core_foundation::{kCFRunLoopDefaultMode, CFRunLoop, CFRunLoopRunResult};
use objc2_foundation::{NSDistributedNotificationCenter, NSNotification, NSObject, NSString};

use crate::auto_lock::{OsLockReason, SecurityEvent};
use crate::error::SecurityError;

use super::{OsLockEventSource, ShutdownHandle};

/// The private distributed-notification name macOS posts when the
/// screen locks. No public header declares it; see the module rustdoc
/// "Deviations" / "Known fragility" sections.
const SCREEN_IS_LOCKED: &str = "com.apple.screenIsLocked";

/// How long each `CFRunLoopRunInMode` slice blocks before the run loop
/// re-checks the shutdown flag. Bounds shutdown latency: `run` returns
/// within one slice of the [`ShutdownHandle`] firing.
const RUN_LOOP_TICK_SECONDS: f64 = 0.25;

/// Instance variables for [`Observer`]. `mpsc::Sender::send` takes
/// `&self`, so the sender needs no interior-mutability wrapper; the
/// observer is touched only on its own run-loop thread regardless.
struct ObserverIvars {
    sender: Sender<SecurityEvent>,
}

define_class!(
    // SAFETY:
    // - The superclass `NSObject` has no subclassing requirements.
    // - `Observer` does not implement `Drop` (its `ObserverIvars` is
    //   dropped by objc2's generated dealloc).
    #[unsafe(super(NSObject))]
    #[name = "FalachIoKitObserver"]
    #[ivars = ObserverIvars]
    struct Observer;

    impl Observer {
        /// Selector target for `com.apple.screenIsLocked`.
        #[unsafe(method(screenLocked:))]
        fn screen_locked(&self, _notification: &NSNotification) {
            // A send-error means the controller dropped its receiver;
            // nothing to do — the run loop exits on the next
            // shutdown-flag check anyway.
            let _ = self.ivars().sender.send(SecurityEvent::OsLock {
                reason: OsLockReason::Screensaver,
            });
        }

        /// Selector target for `NSWorkspaceWillSleepNotification`.
        #[unsafe(method(willSleep:))]
        fn will_sleep(&self, _notification: &NSNotification) {
            let _ = self.ivars().sender.send(SecurityEvent::OsLock {
                reason: OsLockReason::Sleep,
            });
        }
    }
);

impl Observer {
    fn new(sender: Sender<SecurityEvent>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(ObserverIvars { sender });
        // SAFETY: `init` is `NSObject`'s designated initialiser; the
        // ivars are fully set above.
        unsafe { msg_send![super(this), init] }
    }
}

/// `OsLockEventSource` that maps macOS sleep / screen-lock events onto
/// `SecurityEvent::OsLock`.
///
/// Construct with [`Self::new`]; attach via
/// [`crate::auto_lock::AutoLockController::attach_event_source`].
pub struct IoKitSource {
    /// Set by the [`ShutdownHandle`]; polled by the run loop.
    should_stop: Arc<AtomicBool>,
}

impl IoKitSource {
    /// Construct an [`IoKitSource`].
    ///
    /// Lazy, like [`crate::os_events::LogindSource::new`]: registers no
    /// observers and starts no run loop here. The OS resources are
    /// acquired in [`OsLockEventSource::run`] on the source's own
    /// thread, because notification delivery is bound to the run loop
    /// of the thread that registered the observer.
    ///
    /// # Errors
    ///
    /// Currently infallible; the return type is `Result` for symmetry
    /// with the other sources (`SigstopSource::new`,
    /// `LogindSource::new`).
    pub fn new() -> Result<Self, SecurityError> {
        Ok(Self {
            should_stop: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl OsLockEventSource for IoKitSource {
    fn run(self: Box<Self>, sender: Sender<SecurityEvent>) -> Result<(), SecurityError> {
        let should_stop = self.should_stop.clone();

        // The observer must be created and registered on THIS thread —
        // the one whose `CFRunLoop` we pump below — because both
        // notification centers deliver to the run loop of the
        // registering thread.
        let observer = Observer::new(sender);
        let observer_ref: &AnyObject = &observer;

        // Screen lock via the distributed notification center.
        let dist_center = NSDistributedNotificationCenter::defaultCenter();
        let screen_lock_name = NSString::from_str(SCREEN_IS_LOCKED);
        // SAFETY: `observer_ref` is a live objc object implementing the
        // `screenLocked:` selector; `screen_lock_name` outlives the
        // call; `object: None` matches "any sender".
        unsafe {
            dist_center.addObserver_selector_name_object(
                observer_ref,
                sel!(screenLocked:),
                Some(&screen_lock_name),
                None,
            );
        }

        // System sleep via the NSWorkspace notification center.
        let workspace = NSWorkspace::sharedWorkspace();
        let ws_center = workspace.notificationCenter();
        // SAFETY: `observer_ref` implements `willSleep:`;
        // `NSWorkspaceWillSleepNotification` is a framework `extern`
        // static valid for the process lifetime.
        unsafe {
            ws_center.addObserver_selector_name_object(
                observer_ref,
                sel!(willSleep:),
                Some(NSWorkspaceWillSleepNotification),
                None,
            );
        }

        // Pump the run loop until the controller signals shutdown.
        while !should_stop.load(Ordering::Relaxed) {
            autoreleasepool(|_pool| {
                // SAFETY: reading the framework `extern` static run-loop
                // mode constant; valid for the process lifetime.
                let mode = unsafe { kCFRunLoopDefaultMode };
                let result = CFRunLoop::run_in_mode(mode, RUN_LOOP_TICK_SECONDS, false);
                // With observers registered the loop has input sources
                // and blocks until an event or the slice timeout. If it
                // ever returns `Finished` (no sources), avoid a busy
                // spin.
                if result == CFRunLoopRunResult::Finished {
                    std::thread::sleep(Duration::from_millis(50));
                }
            });
        }

        // Deregister before returning so the notification centers drop
        // their references to the observer — the leak T5.0 exists to
        // prevent.
        // SAFETY: `observer_ref` was registered with both centers above.
        unsafe {
            dist_center.removeObserver(observer_ref);
            ws_center.removeObserver(observer_ref);
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "iokit"
    }

    fn shutdown_handle(&mut self) -> ShutdownHandle {
        let flag = self.should_stop.clone();
        ShutdownHandle::new(move || {
            flag.store(true, Ordering::Relaxed);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // All three tests are `#[ignore]`d so they stay out of the default
    // `make check` sweep and run as a bundle on a macOS dev machine via
    // `make test-os-events` (which invokes them with `--ignored`).
    // `name`/`new` don't touch Apple frameworks (`new` is lazy, like
    // `LogindSource::new`), but they're feature-gated to `iokit` and
    // grouped with the run-loop test so the whole macOS source is
    // exercised by one target.

    #[test]
    #[ignore = "iokit-feature-gated; run on a macOS dev machine via `make test-os-events`"]
    fn name_returns_iokit() {
        let source = IoKitSource::new().expect("IoKitSource::new infallible");
        assert_eq!(source.name(), "iokit");
    }

    #[test]
    #[ignore = "iokit-feature-gated; run on a macOS dev machine via `make test-os-events`"]
    fn new_succeeds_on_macos() {
        let _source = IoKitSource::new().expect("IoKitSource::new on macOS");
    }

    /// Phase 5 T5.0 contract: `run` returns `Ok(())` within the drop
    /// budget after the shutdown handle fires. Registers the real
    /// observers and pumps a real `CFRunLoop`, so it is `#[ignore]`d
    /// and run on a macOS dev machine. Mirrors
    /// `noop::tests::run_returns_ok_when_shutdown_signaled` /
    /// `sigstop::tests::run_returns_ok_when_shutdown_signaled`.
    #[test]
    #[ignore = "pumps a real CFRunLoop; run on a macOS dev machine via `make test-os-events`"]
    fn run_returns_ok_when_shutdown_signaled() {
        use std::sync::mpsc;

        let mut source = IoKitSource::new().expect("IoKitSource::new on macOS");
        let shutdown = source.shutdown_handle();
        let (sender_for_run, _drop_receiver) = mpsc::channel::<SecurityEvent>();
        let (result_tx, result_rx) = mpsc::channel::<Result<(), SecurityError>>();

        let worker = std::thread::spawn(move || {
            let outcome = Box::new(source).run(sender_for_run);
            let _ = result_tx.send(outcome);
        });

        shutdown.signal();

        // One run-loop slice (RUN_LOOP_TICK_SECONDS) plus generous
        // scheduling slack.
        match result_rx.recv_timeout(Duration::from_millis(1500)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("IoKitSource::run returned Err: {e:?}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("IoKitSource::run did not return within 1.5s after shutdown signal")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("worker channel closed unexpectedly")
            }
        }
        worker.join().expect("worker thread panicked");
    }
}
