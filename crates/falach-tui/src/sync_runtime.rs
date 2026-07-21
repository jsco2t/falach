//! `SyncRuntime` — the background sync worker over `falach_sync::Sync` (T6.1 /
//! ADR-T4a).
//!
//! The worker **takes ownership of the moved vault** (and the registry) for the
//! duration of a sync: `App.vault.take()` → spawn → `sync_now(&mut vault, …)` →
//! hand both back on completion. While a sync is in flight `App.vault` is `None`,
//! so the UI stays responsive (ticks, lock countdown, cancel/quit) but the vault
//! content is briefly unavailable. There is no concurrent-edit race because the
//! App cannot edit a vault it does not hold.
//!
//! **Master-password handling (ADR-T4):** the `App` never retains a
//! `MasterPassword`. One is moved into [`SyncRuntime::start`] per sync and is
//! dropped (zeroized) on the worker thread the moment `sync_now` returns.
//!
//! **No cancellation hook:** `falach_sync`'s `sync_now` exposes only
//! `max_retries` + `on_activity` (no cancel). A lock that fires mid-sync is
//! therefore *deferred* by the App until the worker returns (the App marks
//! "lock pending"; on completion the vault is dropped+zeroized → `LockScreen`).
//!
//! **The engine seam:** there is no upstream `Sync` *trait* to mock — `Sync` is
//! a concrete struct and `falach_sync`'s `MemoryTransport` can't be injected
//! through the public `sync_now` (it builds the transport from registry config
//! internally). So this module declares a local [`SyncEngine`] trait exactly
//! like Phase 5's `ClipboardSink`: the real impl delegates to
//! `falach_sync::Sync::sync_now`; tests inject a fake to control timing and
//! outcomes.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;
use std::thread;

use falach_core::{MasterPassword, Vault, VaultRegistry};
use falach_sync::{Sync, SyncError, SyncOptions, SyncOutcome};

/// Which trigger initiated a sync. Echoed back in [`SyncResult`] so the App
/// knows what to do when it completes (e.g. lock or quit after an on-lock/quit
/// flush).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncTrigger {
    /// The `s` key (re-prompts the master password).
    Manual,
    /// Auto-sync immediately after a successful unlock.
    OnUnlock,
    /// Flush before a manual lock (`Ctrl+L`).
    OnLock,
    /// Flush before quitting (`Ctrl+Q`).
    OnQuit,
}

/// A message from the sync worker to the main loop.
pub(crate) enum SyncMsg {
    /// A network boundary was crossed; the main loop pings `register_activity`
    /// so a *progressing* sync does not trip idle auto-lock.
    Activity,
    /// The sync finished; carries the moved vault + registry back plus the
    /// outcome. Boxed because [`SyncResult`] is large (it owns a `Vault`).
    Done(Box<SyncResult>),
    /// The worker thread vanished without sending a terminal [`SyncMsg::Done`] —
    /// i.e. it panicked mid-sync (the only path that drops the sender without a
    /// `Done`). The moved vault + registry are gone with the unwound stack; the
    /// App reloads the registry from disk and drops to `LockScreen` (ADR-T4a's
    /// "any sync failure → `LockScreen`", extended to a worker panic).
    /// Synthesized
    /// by [`SyncRuntime::drain`] on a `Disconnected` channel, never sent by the
    /// worker itself.
    WorkerLost,
}

/// The completed sync handed back to the App: the moved vault and registry, the
/// outcome, and the trigger that started it.
pub(crate) struct SyncResult {
    pub(crate) vault: Vault,
    pub(crate) registry: VaultRegistry,
    pub(crate) outcome: Result<SyncOutcome, SyncError>,
    pub(crate) trigger: SyncTrigger,
}

/// The engine seam (see module docs). `Send + Sync` so the `Arc<dyn SyncEngine>`
/// can cross to the worker thread. (`std::marker::Sync` is spelled out because
/// `falach_sync::Sync` — the concrete orchestrator struct — is in scope.)
pub(crate) trait SyncEngine: Send + std::marker::Sync {
    /// Run one sync against the vault's configured remote.
    fn sync_now(
        &self,
        vault: &mut Vault,
        vault_name: &str,
        registry: &mut VaultRegistry,
        master_password: &MasterPassword,
        opts: SyncOptions,
    ) -> Result<SyncOutcome, SyncError>;
}

/// Production engine: forwards to `falach_sync::Sync::sync_now`. The keyfile is
/// `None` for MVP, matching the unlock path (the keyfile-unlock follow-up is
/// tracked as DI-2 in `app.rs`).
pub(crate) struct RealSyncEngine;

impl SyncEngine for RealSyncEngine {
    fn sync_now(
        &self,
        vault: &mut Vault,
        vault_name: &str,
        registry: &mut VaultRegistry,
        master_password: &MasterPassword,
        opts: SyncOptions,
    ) -> Result<SyncOutcome, SyncError> {
        Sync::sync_now(vault, vault_name, registry, master_password, None, opts)
    }
}

/// Drives background syncs. Owns the engine; holds the receiving end of the
/// worker channel while a sync is in flight.
pub(crate) struct SyncRuntime {
    engine: Arc<dyn SyncEngine>,
    inflight: Option<Receiver<SyncMsg>>,
}

impl SyncRuntime {
    /// A runtime backed by the real `falach_sync::Sync` engine.
    pub(crate) fn new() -> Self {
        Self {
            engine: Arc::new(RealSyncEngine),
            inflight: None,
        }
    }

    /// Test seam: a runtime backed by an injected (fake) engine.
    #[cfg(test)]
    pub(crate) fn with_engine(engine: Arc<dyn SyncEngine>) -> Self {
        Self {
            engine,
            inflight: None,
        }
    }

    /// Whether a sync is currently in flight (vault moved to the worker).
    pub(crate) fn is_syncing(&self) -> bool {
        self.inflight.is_some()
    }

    /// Move the vault + registry to a worker thread and run a sync. The master
    /// password is moved in and dropped (zeroized) when the sync completes.
    ///
    /// Caller contract: only call when **not** already syncing (the App gates
    /// this); a second call would replace the receiver and orphan the first
    /// worker's result.
    pub(crate) fn start(
        &mut self,
        vault: Vault,
        registry: VaultRegistry,
        vault_name: String,
        master_password: MasterPassword,
        trigger: SyncTrigger,
    ) {
        let (tx, rx) = mpsc::channel();
        let engine = Arc::clone(&self.engine);
        let activity_tx = tx.clone();
        thread::spawn(move || {
            let mut vault = vault;
            let mut registry = registry;
            let opts = SyncOptions {
                on_activity: Some(Box::new(move || {
                    // The controller is `!Send` and lives on the main thread, so
                    // we ping it indirectly: send an Activity message the main
                    // loop turns into `register_activity` (drained before the
                    // lock check in `App::tick`).
                    let _ = activity_tx.send(SyncMsg::Activity);
                })),
                ..SyncOptions::default()
            };
            let outcome = engine.sync_now(
                &mut vault,
                &vault_name,
                &mut registry,
                &master_password,
                opts,
            );
            // `master_password` drops here → zeroized on this thread, never
            // retained by the App.
            let _ = tx.send(SyncMsg::Done(Box::new(SyncResult {
                vault,
                registry,
                outcome,
                trigger,
            })));
        });
        self.inflight = Some(rx);
    }

    /// Drain pending worker messages without blocking. Clears the in-flight
    /// handle once the terminal `Done` arrives (so a subsequent `Done` can never
    /// be observed twice).
    pub(crate) fn drain(&mut self) -> Vec<SyncMsg> {
        let mut msgs = Vec::new();
        let mut finished = false;
        if let Some(rx) = self.inflight.as_ref() {
            loop {
                match rx.try_recv() {
                    Ok(msg) => {
                        let done = matches!(msg, SyncMsg::Done(_));
                        msgs.push(msg);
                        if done {
                            finished = true;
                            break;
                        }
                    }
                    // Worker alive, nothing pending yet — try again next tick.
                    Err(TryRecvError::Empty) => break,
                    // Sender dropped *without* a `Done`: the worker panicked.
                    // Surface a synthetic terminal `WorkerLost` so the App can
                    // recover instead of hanging on "Syncing…" forever, and
                    // clear `inflight` so `is_syncing()` goes false.
                    Err(TryRecvError::Disconnected) => {
                        msgs.push(SyncMsg::WorkerLost);
                        finished = true;
                        break;
                    }
                }
            }
        }
        if finished {
            self.inflight = None;
        }
        msgs
    }
}

/// Compile-time gate (ADR-T4a): the move-to-worker model requires the moved
/// values to be `Send`. If this stops compiling, `Vault` lost `Send` and the
/// synchronous-fallback path (a brief blocking spinner) becomes mandatory.
#[allow(dead_code)]
fn _assert_worker_payload_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<Vault>();
    assert_send::<VaultRegistry>();
    assert_send::<MasterPassword>();
    assert_send::<SyncResult>();
    assert_send::<SyncMsg>();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake engine that returns a canned outcome without touching the network.
    /// (The vault/registry pass through untouched — enough for the runtime's
    /// pipe behaviour; the App-level outcome handling is tested directly in
    /// `app.rs` by constructing `SyncMsg::Done` values.)
    struct FakeEngine {
        outcome: fn() -> Result<SyncOutcome, SyncError>,
        ping_activity: bool,
    }

    impl SyncEngine for FakeEngine {
        fn sync_now(
            &self,
            _vault: &mut Vault,
            _vault_name: &str,
            _registry: &mut VaultRegistry,
            _master_password: &MasterPassword,
            mut opts: SyncOptions,
        ) -> Result<SyncOutcome, SyncError> {
            if self.ping_activity {
                if let Some(ping) = opts.on_activity.as_mut() {
                    ping();
                }
            }
            (self.outcome)()
        }
    }

    fn fixture() -> (Vault, VaultRegistry, MasterPassword, String) {
        use falach_core::{FalachPaths, KdfParams, NoRecoveryConfirmed};
        let dir = tempfile::tempdir().expect("tempdir");
        // Keep the tempdir so the on-disk vault outlives this helper; tests are
        // short-lived processes.
        let path = dir.keep().join("v.kdbx");
        let mp = MasterPassword::new("pw".to_string());
        let vault = Vault::create(
            &path,
            &mp,
            None,
            KdfParams {
                memory_kib: 1_024,
                iterations: 1,
                parallelism: 1,
            },
            NoRecoveryConfirmed::yes(),
        )
        .expect("create");
        let registry = VaultRegistry::with_paths(FalachPaths::with_state_dir(
            path.parent().unwrap().join("state"),
        ));
        (vault, registry, mp, "v".to_string())
    }

    #[test]
    fn drain_yields_activity_then_done_and_clears_inflight() {
        let (vault, registry, mp, name) = fixture();
        let mut rt = SyncRuntime::with_engine(Arc::new(FakeEngine {
            outcome: || Ok(SyncOutcome::AlreadyInSync),
            ping_activity: true,
        }));
        rt.start(vault, registry, name, mp, SyncTrigger::Manual);

        // Block until the worker has finished by polling drain (no sleep API).
        let mut all = Vec::new();
        for _ in 0..100_000 {
            all.extend(rt.drain());
            if all.iter().any(|m| matches!(m, SyncMsg::Done(_))) {
                break;
            }
        }
        assert!(
            all.iter().any(|m| matches!(m, SyncMsg::Activity)),
            "the fake engine pinged on_activity"
        );
        let done = all
            .iter()
            .find_map(|m| match m {
                SyncMsg::Done(r) => Some(r),
                SyncMsg::Activity | SyncMsg::WorkerLost => None,
            })
            .expect("a Done message arrived");
        assert!(matches!(done.outcome, Ok(SyncOutcome::AlreadyInSync)));
        assert_eq!(done.trigger, SyncTrigger::Manual);
        assert!(!rt.is_syncing(), "inflight cleared after Done drained");
    }

    #[test]
    fn drain_on_worker_disconnect_yields_worker_lost_and_clears_inflight() {
        // Simulate a worker that vanished without sending `Done` (a panic
        // mid-sync drops the sender, disconnecting the channel). `drain` must
        // surface `WorkerLost` and clear `inflight` so the UI does not hang on
        // "Syncing…" forever.
        let (tx, rx) = mpsc::channel::<SyncMsg>();
        drop(tx); // no `Done` is ever sent → the next `try_recv` is Disconnected
        let mut rt = SyncRuntime {
            engine: Arc::new(FakeEngine {
                outcome: || Ok(SyncOutcome::AlreadyInSync),
                ping_activity: false,
            }),
            inflight: Some(rx),
        };
        assert!(rt.is_syncing(), "inflight is set before draining");
        let msgs = rt.drain();
        assert!(
            msgs.iter().any(|m| matches!(m, SyncMsg::WorkerLost)),
            "a disconnect without `Done` surfaces `WorkerLost`"
        );
        assert!(!rt.is_syncing(), "inflight cleared after a lost worker");
    }

    #[test]
    fn not_syncing_before_start() {
        let rt = SyncRuntime::new();
        assert!(!rt.is_syncing());
    }
}
