use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use falach_core::{FalachPaths, Keyfile, MasterPassword, Vault, VaultRegistry};
use falach_security::{AutoLockConfig, AutoLockController, LockState, OsLockReason};
use zeroize::Zeroize;

use crate::dto::{AppInitConfig, KeyfileRef, LifecycleStateDto, LockEvent, VaultTree};
use crate::error::FalachApiError;
use crate::event::EventSink;

const LIFECYCLE_GRACE_SECS: u64 = 15;

static HARDENED: OnceLock<()> = OnceLock::new();

fn epoch_millis_now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}

fn lifecycle_from_u8(v: u8) -> LifecycleStateDto {
    match v {
        1 => LifecycleStateDto::Inactive,
        2 => LifecycleStateDto::Hidden,
        3 => LifecycleStateDto::Paused,
        4 => LifecycleStateDto::Detached,
        _ => LifecycleStateDto::Resumed,
    }
}

fn lifecycle_to_u8(state: LifecycleStateDto) -> u8 {
    match state {
        LifecycleStateDto::Resumed => 0,
        LifecycleStateDto::Inactive => 1,
        LifecycleStateDto::Hidden => 2,
        LifecycleStateDto::Paused => 3,
        LifecycleStateDto::Detached => 4,
    }
}

// ---------------------------------------------------------------------------
// SessionCredentials — D-11: retained master password + optional keyfile
// ---------------------------------------------------------------------------

struct SessionCredentials {
    #[allow(dead_code)] // read by T1.6 (sync worker needs &MasterPassword)
    master: MasterPassword,
    keyfile: Option<Keyfile>,
}

// MasterPassword and Keyfile both implement ZeroizeOnDrop individually.
// SessionCredentials owns them; dropping it drops them, which zeroizes.
// No additional Zeroize impl is needed — ownership-based zeroize.
impl Drop for SessionCredentials {
    fn drop(&mut self) {
        // Fields are dropped (and therefore zeroized) automatically.
        // Explicit take ensures deterministic ordering.
        drop(self.keyfile.take());
    }
}

impl std::fmt::Debug for SessionCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionCredentials(***)")
    }
}

// ---------------------------------------------------------------------------
// SessionState — the mutex-protected interior
// ---------------------------------------------------------------------------

struct SessionState {
    registry: VaultRegistry,
    vault: Option<Vault>,
    credentials: Option<SessionCredentials>,
    controller: AutoLockController,
    #[allow(dead_code)] // T1.6 sync support
    lock_pending: bool,
    lock_sink: Option<Box<dyn EventSink<LockEvent>>>,
}

impl SessionState {
    fn push_lock_event(&self, event: LockEvent) {
        if let Some(ref sink) = self.lock_sink {
            sink.send(event);
        }
    }

    fn do_lock(&mut self) {
        self.vault = None;
        self.credentials = None;
        self.controller.lock_now(OsLockReason::Manual);
        self.push_lock_event(LockEvent::Locked);
    }

    fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }
}

// ---------------------------------------------------------------------------
// AppSession — the opaque FFI boundary type
// ---------------------------------------------------------------------------

pub struct AppSession {
    inner: Arc<Mutex<SessionState>>,
    last_activity: Arc<AtomicI64>,
    lifecycle_state: Arc<AtomicU8>,
    ticker_shutdown: Arc<AtomicBool>,
    ticker_join: Mutex<Option<JoinHandle<()>>>,
    #[cfg(any(test, feature = "test-fixtures"))]
    test_grace_start: Mutex<Option<Instant>>,
    #[cfg(any(test, feature = "test-fixtures"))]
    test_last_seen: Mutex<i64>,
}

impl std::fmt::Debug for AppSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppSession")
            .field(
                "has_ticker",
                &self.ticker_join.lock().ok().map(|g| g.is_some()),
            )
            .finish_non_exhaustive()
    }
}

pub fn init_app(cfg: &AppInitConfig) -> Result<AppSession, FalachApiError> {
    HARDENED.get_or_init(|| {
        falach_security::harden_process();
    });

    let paths = match (&cfg.state_dir, &cfg.config_dir) {
        (Some(state), Some(config)) => {
            FalachPaths::with_state_dir(PathBuf::from(state)).with_config_dir(PathBuf::from(config))
        }
        (Some(state), None) => FalachPaths::with_state_dir(PathBuf::from(state)),
        _ => FalachPaths::from_env()?,
    };
    paths.ensure_exists()?;

    let registry = VaultRegistry::load(paths)?;

    let controller = AutoLockController::new(AutoLockConfig::default()).map_err(|e| {
        FalachApiError::Internal {
            context: format!("auto-lock controller init: {e}"),
        }
    })?;

    let state = SessionState {
        registry,
        vault: None,
        credentials: None,
        controller,
        lock_pending: false,
        lock_sink: None,
    };

    let inner = Arc::new(Mutex::new(state));
    let last_activity = Arc::new(AtomicI64::new(0));
    let lifecycle_state = Arc::new(AtomicU8::new(lifecycle_to_u8(LifecycleStateDto::Resumed)));
    let ticker_shutdown = Arc::new(AtomicBool::new(false));

    let ticker_join = spawn_ticker(
        Arc::clone(&inner),
        Arc::clone(&last_activity),
        Arc::clone(&lifecycle_state),
        Arc::clone(&ticker_shutdown),
    );

    Ok(AppSession {
        inner,
        last_activity,
        lifecycle_state,
        ticker_shutdown,
        ticker_join: Mutex::new(Some(ticker_join)),
        #[cfg(any(test, feature = "test-fixtures"))]
        test_grace_start: Mutex::new(None),
        #[cfg(any(test, feature = "test-fixtures"))]
        test_last_seen: Mutex::new(0),
    })
}

impl AppSession {
    pub fn lock_events(&self, sink: Box<dyn EventSink<LockEvent>>) {
        let mut state = self.lock_state();
        state.lock_sink = Some(sink);
    }

    pub fn report_activity(&self) {
        self.last_activity
            .store(epoch_millis_now(), Ordering::Relaxed);
    }

    pub fn report_lifecycle_state(&self, state: LifecycleStateDto) {
        self.lifecycle_state
            .store(lifecycle_to_u8(state), Ordering::Relaxed);
    }

    #[allow(clippy::needless_pass_by_value)] // frb FFI passes owned values
    pub fn unlock(
        &self,
        name: &str,
        master_password: String,
        keyfile: Option<KeyfileRef>,
    ) -> Result<VaultTree, FalachApiError> {
        let mut master = MasterPassword::new(master_password);
        let kf = keyfile.as_ref().map(|kr| match kr {
            KeyfileRef::Path(p) => Keyfile::Path(PathBuf::from(p)),
            KeyfileRef::Bytes(b) => Keyfile::Bytes(b.clone()),
        });

        let mut state = self.lock_state();

        if state.is_unlocked() {
            master.zeroize();
            return Err(FalachApiError::Internal {
                context: "a vault is already unlocked".to_string(),
            });
        }

        let vault_path = state
            .registry
            .get(name)
            .ok_or_else(|| FalachApiError::FileNotFound {
                path: name.to_string(),
            })?
            .path
            .clone();

        let vault = Vault::open(&vault_path, &master, kf.as_ref())?;

        let now = Instant::now();
        state.controller.unlock(now);
        self.last_activity
            .store(epoch_millis_now(), Ordering::Relaxed);

        let tree = crate::dto::vault_tree_from_database(vault.database(), chrono::Utc::now());

        state.credentials = Some(SessionCredentials {
            master,
            keyfile: kf,
        });
        state.vault = Some(vault);

        state.push_lock_event(LockEvent::Unlocked);

        Ok(tree)
    }

    pub fn lock_now(&self) -> Result<(), FalachApiError> {
        let mut state = self.lock_state();
        if state.is_unlocked() {
            state.do_lock();
        }
        Ok(())
    }

    pub fn shutdown(&self) {
        self.ticker_shutdown.store(true, Ordering::Relaxed);

        {
            let mut state = self.lock_state();
            if state.is_unlocked() {
                state.do_lock();
            }
        }

        if let Ok(mut guard) = self.ticker_join.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, SessionState> {
        self.inner.lock().unwrap_or_else(|poison| {
            let mut state = poison.into_inner();
            state.vault = None;
            state.credentials = None;
            state.push_lock_event(LockEvent::Locked);
            state
        })
    }
}

// ---------------------------------------------------------------------------
// Test-only API — manual tick driving without wall-clock sleeps.
// Moved to `test-fixtures` feature in T1.7.
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-fixtures"))]
#[allow(clippy::missing_panics_doc)]
impl AppSession {
    pub fn for_test(paths: FalachPaths) -> Result<Self, FalachApiError> {
        let registry = VaultRegistry::load(paths)?;
        let controller = AutoLockController::new(AutoLockConfig::default()).map_err(|e| {
            FalachApiError::Internal {
                context: format!("controller init: {e}"),
            }
        })?;

        let state = SessionState {
            registry,
            vault: None,
            credentials: None,
            controller,
            lock_pending: false,
            lock_sink: None,
        };

        Ok(Self {
            inner: Arc::new(Mutex::new(state)),
            last_activity: Arc::new(AtomicI64::new(0)),
            lifecycle_state: Arc::new(AtomicU8::new(0)),
            ticker_shutdown: Arc::new(AtomicBool::new(false)),
            ticker_join: Mutex::new(None),
            #[cfg(any(test, feature = "test-fixtures"))]
            test_grace_start: Mutex::new(None),
            #[cfg(any(test, feature = "test-fixtures"))]
            test_last_seen: Mutex::new(0),
        })
    }

    pub fn for_test_with_timeout(
        paths: FalachPaths,
        idle_timeout: Duration,
    ) -> Result<Self, FalachApiError> {
        let registry = VaultRegistry::load(paths)?;
        let config = AutoLockConfig { idle_timeout };
        let controller = AutoLockController::new(config).map_err(|e| FalachApiError::Internal {
            context: format!("controller init: {e}"),
        })?;

        let state = SessionState {
            registry,
            vault: None,
            credentials: None,
            controller,
            lock_pending: false,
            lock_sink: None,
        };

        Ok(Self {
            inner: Arc::new(Mutex::new(state)),
            last_activity: Arc::new(AtomicI64::new(0)),
            lifecycle_state: Arc::new(AtomicU8::new(0)),
            ticker_shutdown: Arc::new(AtomicBool::new(false)),
            ticker_join: Mutex::new(None),
            #[cfg(any(test, feature = "test-fixtures"))]
            test_grace_start: Mutex::new(None),
            #[cfg(any(test, feature = "test-fixtures"))]
            test_last_seen: Mutex::new(0),
        })
    }

    pub fn drive_tick(&self, now: Instant) {
        let activity_millis = self.last_activity.load(Ordering::Relaxed);
        let lifecycle = lifecycle_from_u8(self.lifecycle_state.load(Ordering::Relaxed));

        let mut grace = self.test_grace_start.lock().expect("grace lock");
        let mut last_seen = self.test_last_seen.lock().expect("last_seen lock");
        let mut state = self.lock_state();
        tick_inner(
            &mut state,
            now,
            activity_millis,
            lifecycle,
            &mut grace,
            &mut last_seen,
        );
    }

    pub fn has_vault(&self) -> bool {
        self.lock_state().is_unlocked()
    }

    pub fn has_credentials(&self) -> bool {
        self.lock_state().credentials.is_some()
    }

    pub fn hold_mutex_for_test(&self) -> impl Drop + '_ {
        self.lock_state()
    }
}

// ---------------------------------------------------------------------------
// Ticker thread
// ---------------------------------------------------------------------------

fn spawn_ticker(
    inner: Arc<Mutex<SessionState>>,
    last_activity: Arc<AtomicI64>,
    lifecycle_state: Arc<AtomicU8>,
    shutdown: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("falach-api-ticker".to_string())
        .spawn(move || {
            let mut last_seen_activity: i64 = 0;
            let mut grace_start: Option<Instant> = None;

            loop {
                thread::sleep(Duration::from_secs(1));

                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                let activity_millis = last_activity.load(Ordering::Relaxed);
                let lifecycle = lifecycle_from_u8(lifecycle_state.load(Ordering::Relaxed));

                let Ok(mut state) = inner.try_lock() else {
                    continue;
                };

                tick_inner(
                    &mut state,
                    Instant::now(),
                    activity_millis,
                    lifecycle,
                    &mut grace_start,
                    &mut last_seen_activity,
                );
            }
        })
        .expect("failed to spawn ticker thread")
}

fn tick_inner(
    state: &mut SessionState,
    now: Instant,
    activity_millis: i64,
    lifecycle: LifecycleStateDto,
    grace_start: &mut Option<Instant>,
    last_seen_activity: &mut i64,
) {
    if activity_millis != 0 && activity_millis != *last_seen_activity {
        state.controller.register_activity(now);
    }
    *last_seen_activity = activity_millis;

    let lock_state = state.controller.tick(now);

    let mut should_lock = false;

    match lifecycle {
        LifecycleStateDto::Resumed => {
            if grace_start.take().is_some() {
                state.controller.register_activity(now);
            }
        }
        LifecycleStateDto::Inactive => {}
        LifecycleStateDto::Hidden | LifecycleStateDto::Paused => {
            if grace_start.is_none() {
                *grace_start = Some(now);
            } else if let Some(started) = *grace_start {
                if now.duration_since(started) >= Duration::from_secs(LIFECYCLE_GRACE_SECS) {
                    should_lock = true;
                    *grace_start = None;
                }
            }
        }
        LifecycleStateDto::Detached => {
            should_lock = true;
            *grace_start = None;
        }
    }

    if lock_state == LockState::Locked {
        should_lock = true;
    }

    if should_lock && state.is_unlocked() {
        state.do_lock();
    }
}
