//! `LogindSource` — Linux systemd-logind [`OsLockEventSource`].
//!
//! Subscribes to two `DBus` signals via `zbus`:
//!
//! - `org.freedesktop.login1.Manager.PrepareForSleep(bool)` on the
//!   system bus. Fires with `start = true` *before* the system
//!   suspends; we map this to `OsLock { reason: Sleep }`. The
//!   `start = false` (resume) variant is observed but ignored — the
//!   user re-authenticates via `unlock()` regardless.
//! - `org.freedesktop.login1.Session.Lock` on the system bus, on the
//!   current session's object path. Fires when the session is
//!   locked (e.g., the desktop environment's screensaver kicks in
//!   on most setups). We map this to
//!   `OsLock { reason: Screensaver }`.
//!
//! Both signals are subscribed on the **system bus**. The session
//! object path is resolved at construction time via
//! `Manager.GetSessionByPID(getpid())`.
//!
//! ## Cargo feature gate
//!
//! Compiled only when `falach-security/logind` is enabled. The
//! feature is **default-off** so a plain `cargo build` does not pull
//! the `zbus` + `async-io` dependency trees. Consumers (the TUI / CLI
//! / agent crates) opt in via their own `Cargo.toml`.
//!
//! ## Shutdown (Phase 5 T5.0 contract)
//!
//! The source owns an `async-channel::Sender<()>` whose receiver is
//! racing the signal streams. On controller drop, the
//! [`ShutdownHandle`] returned by
//! [`OsLockEventSource::shutdown_handle`] drops the sender; the
//! receiver's `recv` resolves with `Err`, the race finishes with
//! "shutdown", the run loop breaks, and `run` returns `Ok(())`. The
//! held `DBus` connections drop and zbus tears them down cleanly.

use std::sync::mpsc::Sender as StdSender;

use async_channel::{Receiver as AsyncRx, Sender as AsyncTx};
use futures_lite::StreamExt;
use zbus::Proxy;

use crate::auto_lock::{OsLockReason, SecurityEvent};
use crate::error::SecurityError;

use super::{OsLockEventSource, ShutdownHandle};

const LOGIND_SERVICE: &str = "org.freedesktop.login1";
const LOGIND_MANAGER_PATH: &str = "/org/freedesktop/login1";
const LOGIND_MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";
const LOGIND_SESSION_IFACE: &str = "org.freedesktop.login1.Session";

/// Outcome of one round of `run_async`'s `futures_lite::or` race.
enum Branch {
    /// `shutdown_rx` closed — controller is dropping us.
    Shutdown,
    /// A `PrepareForSleep` signal arrived with `start = true`/`false`.
    Sleep(zbus::Message),
    /// A `Session.Lock` signal arrived (body unused).
    Lock,
    /// A signal stream returned `None` — `DBus` connection lost or
    /// zbus teardown. Treated as a clean exit.
    StreamEnded,
}

/// `OsLockEventSource` that maps systemd-logind `DBus` signals
/// (`PrepareForSleep`, `Lock`) onto `SecurityEvent::OsLock`.
pub struct LogindSource {
    /// Held until [`Self::shutdown_handle`] is called. Dropping this
    /// closes the channel and unblocks the receiver in `run_async`,
    /// breaking the run loop.
    shutdown_tx: Option<AsyncTx<()>>,
    shutdown_rx: AsyncRx<()>,
}

impl LogindSource {
    /// Construct a [`LogindSource`].
    ///
    /// Lazy: opens no `DBus` connections here — those happen in
    /// [`OsLockEventSource::run`] on the source's thread. This keeps
    /// `attach_event_source` cheap and shifts any DBus-availability
    /// failure into the run loop where the controller can observe
    /// it via the source's exit.
    ///
    /// # Errors
    ///
    /// Currently infallible; the return type is `Result` for symmetry
    /// with the other sources (`SigstopSource::new`).
    pub fn new() -> Result<Self, SecurityError> {
        let (tx, rx) = async_channel::bounded(1);
        Ok(Self {
            shutdown_tx: Some(tx),
            shutdown_rx: rx,
        })
    }
}

impl OsLockEventSource for LogindSource {
    fn run(self: Box<Self>, sender: StdSender<SecurityEvent>) -> Result<(), SecurityError> {
        // `*self` lets us move out of the box; the inner `Box`
        // wrapper is dropped at scope end.
        let LogindSource { shutdown_rx, .. } = *self;
        zbus::block_on(async move { run_async(shutdown_rx, sender).await })
    }

    fn name(&self) -> &'static str {
        "logind"
    }

    fn shutdown_handle(&mut self) -> ShutdownHandle {
        // Take the sender out of `self`; dropping it inside the
        // returned closure closes the channel, which is the
        // run loop's shutdown signal.
        let tx = self
            .shutdown_tx
            .take()
            .expect("LogindSource::shutdown_handle called twice");
        ShutdownHandle::new(move || {
            drop(tx);
        })
    }
}

/// Build the two proxies and subscribe to their signals. Extracted
/// from `run_async` to keep the top-level function shorter than the
/// 100-line clippy limit; also makes the setup easier to audit
/// independently from the streaming loop.
async fn setup_streams(
    system_conn: &zbus::Connection,
) -> Result<(zbus::proxy::SignalStream<'_>, zbus::proxy::SignalStream<'_>), SecurityError> {
    let manager = Proxy::new(
        system_conn,
        LOGIND_SERVICE,
        LOGIND_MANAGER_PATH,
        LOGIND_MANAGER_IFACE,
    )
    .await
    .map_err(|e| SecurityError::EventSourceStart {
        name: "logind",
        detail: format!("build Manager proxy: {e}"),
    })?;

    // Resolve our session's object path so we can subscribe to its
    // per-session Lock signal. Method: GetSessionByPID(uint32 pid)
    // returns the object path of the session containing that pid.
    let our_pid: u32 = std::process::id();
    let session_path: zbus::zvariant::OwnedObjectPath = manager
        .call("GetSessionByPID", &our_pid)
        .await
        .map_err(|e| SecurityError::EventSourceStart {
            name: "logind",
            detail: format!("GetSessionByPID({our_pid}): {e}"),
        })?;

    let session = Proxy::new(
        system_conn,
        LOGIND_SERVICE,
        session_path.as_ref().to_owned(),
        LOGIND_SESSION_IFACE,
    )
    .await
    .map_err(|e| SecurityError::EventSourceStart {
        name: "logind",
        detail: format!("build Session proxy: {e}"),
    })?;

    let prepare_for_sleep = manager
        .receive_signal("PrepareForSleep")
        .await
        .map_err(|e| SecurityError::EventSourceStart {
            name: "logind",
            detail: format!("subscribe PrepareForSleep: {e}"),
        })?;
    let session_lock =
        session
            .receive_signal("Lock")
            .await
            .map_err(|e| SecurityError::EventSourceStart {
                name: "logind",
                detail: format!("subscribe Session.Lock: {e}"),
            })?;
    Ok((prepare_for_sleep, session_lock))
}

async fn run_async(
    shutdown_rx: AsyncRx<()>,
    sender: StdSender<SecurityEvent>,
) -> Result<(), SecurityError> {
    let system_conn =
        zbus::Connection::system()
            .await
            .map_err(|e| SecurityError::EventSourceStart {
                name: "logind",
                detail: format!("connect to system DBus: {e}"),
            })?;
    let (mut prepare_for_sleep, mut session_lock) = setup_streams(&system_conn).await?;

    loop {
        let next = futures_lite::future::or(
            async {
                let _ = shutdown_rx.recv().await;
                Branch::Shutdown
            },
            futures_lite::future::or(
                async {
                    match prepare_for_sleep.next().await {
                        Some(msg) => Branch::Sleep(msg),
                        None => Branch::StreamEnded,
                    }
                },
                async {
                    match session_lock.next().await {
                        Some(_msg) => Branch::Lock,
                        None => Branch::StreamEnded,
                    }
                },
            ),
        )
        .await;

        match next {
            Branch::Shutdown => break,
            Branch::StreamEnded => {
                // A signal stream closing means the DBus connection
                // was lost or zbus is tearing down. Treat as a clean
                // exit; the controller will see its events stop.
                break;
            }
            Branch::Sleep(msg) => {
                // `PrepareForSleep` carries a single bool. Read it;
                // forward `OsLock { Sleep }` only on `true` (the
                // "system is about to suspend" edge). `false` (resume)
                // is observed and ignored — the vault is already locked.
                let starting: bool =
                    msg.body()
                        .deserialize()
                        .map_err(|e| SecurityError::EventSourceStart {
                            name: "logind",
                            detail: format!("parse PrepareForSleep body: {e}"),
                        })?;
                if starting
                    && sender
                        .send(SecurityEvent::OsLock {
                            reason: OsLockReason::Sleep,
                        })
                        .is_err()
                {
                    return Err(SecurityError::EventChannelClosed { name: "logind" });
                }
            }
            Branch::Lock => {
                if sender
                    .send(SecurityEvent::OsLock {
                        reason: OsLockReason::Screensaver,
                    })
                    .is_err()
                {
                    return Err(SecurityError::EventChannelClosed { name: "logind" });
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_returns_logind() {
        let source = LogindSource::new().expect("LogindSource::new infallible");
        assert_eq!(source.name(), "logind");
    }

    #[test]
    fn new_is_lazy_and_does_not_open_dbus() {
        // Sanity check: `new` does not call `Connection::system`. A
        // regression that does would force every consumer onto a
        // system with DBus available at construction time, which
        // would break tests on headless runners that gate logind
        // behind `make test-os-events`.
        let _ = LogindSource::new().expect("LogindSource::new infallible");
    }
}
