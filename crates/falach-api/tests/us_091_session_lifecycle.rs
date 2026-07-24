mod common;

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use falach_api::api::session::{init_app, AppSession};
use falach_api::dto::{AppInitConfig, LifecycleStateDto, LockEvent};
use falach_api::error::FalachApiError;

use common::{create_test_vault, register_vault, RecordingLockSink, TestEnv};

fn session_with_vault(env: &TestEnv, name: &str, password: &str) -> AppSession {
    let vault_path = create_test_vault(env, name, password);
    register_vault(env, name, &vault_path);
    AppSession::for_test(env.paths_clone()).expect("create session")
}

fn session_with_vault_and_sink(
    env: &TestEnv,
    name: &str,
    password: &str,
) -> (AppSession, RecordingLockSink) {
    let session = session_with_vault(env, name, password);
    let (sink, recording) = RecordingLockSink::new();
    session.lock_events(sink);
    (session, recording)
}

fn unlocked_session(env: &TestEnv, name: &str, password: &str) -> (AppSession, RecordingLockSink) {
    let (session, recording) = session_with_vault_and_sink(env, name, password);
    session
        .unlock(name, password.to_string(), None)
        .expect("unlock");
    (session, recording)
}

// ---------------------------------------------------------------------------
// init_app
// ---------------------------------------------------------------------------

#[test]
fn init_creates_session_with_locked_state() {
    let env = TestEnv::new();
    env.paths().ensure_exists().expect("ensure dir");
    let session = AppSession::for_test(env.paths_clone()).expect("init");
    assert!(!session.has_vault(), "session should start with no vault");
    assert!(
        !session.has_credentials(),
        "session should start with no credentials"
    );
}

#[test]
fn init_app_uses_state_dir_from_config() {
    let env = TestEnv::new();
    env.paths().ensure_exists().expect("ensure dir");
    let cfg = AppInitConfig {
        state_dir: Some(env.paths().state_dir().to_string_lossy().to_string()),
        config_dir: None,
    };
    let session = init_app(&cfg).expect("init_app");
    session.shutdown();
}

// ---------------------------------------------------------------------------
// unlock / lock cycle
// ---------------------------------------------------------------------------

#[test]
fn init_unlock_browse_lock_unlock_cycle_maintains_consistent_state() {
    let env = TestEnv::new();
    let name = "test-vault";
    let password = "correct-horse-battery-staple";
    let (session, recording) = session_with_vault_and_sink(&env, name, password);

    assert!(!session.has_vault(), "pre-unlock: no vault");

    let tree = session
        .unlock(name, password.to_string(), None)
        .expect("first unlock");
    assert!(session.has_vault(), "post-unlock: vault present");
    assert!(
        session.has_credentials(),
        "post-unlock: credentials retained (D-11)"
    );
    assert!(!tree.root.uuid.is_empty(), "tree has a root group uuid");

    let events = recording.drain();
    assert!(
        events.iter().any(|e| matches!(e, LockEvent::Unlocked)),
        "unlock event should be emitted"
    );

    session.lock_now().expect("lock");
    assert!(!session.has_vault(), "post-lock: vault dropped");
    assert!(!session.has_credentials(), "post-lock: credentials dropped");

    let events = recording.drain();
    assert!(
        events.iter().any(|e| matches!(e, LockEvent::Locked)),
        "locked event should be emitted"
    );

    let tree2 = session
        .unlock(name, password.to_string(), None)
        .expect("second unlock");
    assert!(session.has_vault(), "re-unlock: vault present");
    assert!(session.has_credentials(), "re-unlock: credentials retained");
    assert_eq!(tree.root.name, tree2.root.name, "same vault tree root");
}

#[test]
fn wrong_password_returns_authentication_failed_and_keeps_session_locked() {
    let env = TestEnv::new();
    let name = "test-vault";
    let (session, _recording) = session_with_vault_and_sink(&env, name, "correct-password");

    let result = session.unlock(name, "wrong-password".to_string(), None);
    assert!(
        matches!(result, Err(FalachApiError::AuthenticationFailed)),
        "expected AuthenticationFailed, got: {result:?}"
    );
    assert!(!session.has_vault(), "no vault after failed unlock");
    assert!(
        !session.has_credentials(),
        "no credentials after failed unlock"
    );
}

#[test]
fn unlock_already_unlocked_returns_error() {
    let env = TestEnv::new();
    let name = "test-vault";
    let password = "test-pass";
    let (session, _recording) = unlocked_session(&env, name, password);

    let result = session.unlock(name, password.to_string(), None);
    assert!(
        matches!(result, Err(FalachApiError::Internal { .. })),
        "double unlock should error: {result:?}"
    );
    assert!(
        session.has_vault(),
        "vault still present after double-unlock attempt"
    );
}

// ---------------------------------------------------------------------------
// Auto-lock via ticker (manual clock injection)
// ---------------------------------------------------------------------------

#[test]
fn tick_past_idle_deadline_drops_vault_and_emits_locked_event() {
    let env = TestEnv::new();
    let name = "test-vault";
    let password = "test-pass";
    let idle_timeout = Duration::from_secs(5);

    let vault_path = create_test_vault(&env, name, password);
    register_vault(&env, name, &vault_path);
    let session =
        AppSession::for_test_with_timeout(env.paths_clone(), idle_timeout).expect("session");
    let (sink, recording) = RecordingLockSink::new();
    session.lock_events(sink);

    session
        .unlock(name, password.to_string(), None)
        .expect("unlock");
    assert!(session.has_vault(), "vault present after unlock");

    let now = Instant::now();

    // First tick picks up the unlock activity and re-registers it at
    // this instant. The idle deadline starts from here.
    session.drive_tick(now);

    session.drive_tick(now + Duration::from_secs(1));
    assert!(session.has_vault(), "vault still present after 1s");

    session.drive_tick(now + Duration::from_secs(4));
    assert!(session.has_vault(), "vault still present after 4s");

    // Tick at 5s — idle deadline fires: Active → Expired
    session.drive_tick(now + Duration::from_secs(5));
    // Tick at 6s — Expired → Locked: vault dropped
    session.drive_tick(now + Duration::from_secs(6));

    assert!(!session.has_vault(), "vault dropped after idle expiry");
    assert!(
        !session.has_credentials(),
        "credentials dropped after idle expiry"
    );

    let events = recording.drain();
    assert!(
        events.iter().any(|e| matches!(e, LockEvent::Locked)),
        "LockEvent::Locked emitted on idle expiry"
    );
}

#[test]
fn report_activity_defers_lock_without_taking_session_mutex() {
    let env = TestEnv::new();
    let name = "test-vault";
    let password = "test-pass";
    let (session, _recording) = unlocked_session(&env, name, password);

    let session = std::sync::Arc::new(session);
    let session2 = std::sync::Arc::clone(&session);

    let _guard = session.hold_mutex_for_test();

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        session2.report_activity();
        tx.send(()).expect("send completion signal");
    });

    rx.recv_timeout(Duration::from_millis(500))
        .expect("report_activity should not block when mutex is held");
}

// ---------------------------------------------------------------------------
// Lifecycle grace (D-12)
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_grace_semantics_match_design_table() {
    let env = TestEnv::new();
    let name = "test-vault";
    let password = "test-pass";
    let idle_timeout = Duration::from_secs(600);

    let vault_path = create_test_vault(&env, name, password);
    register_vault(&env, name, &vault_path);
    let session =
        AppSession::for_test_with_timeout(env.paths_clone(), idle_timeout).expect("session");
    let (sink, recording) = RecordingLockSink::new();
    session.lock_events(sink);
    session
        .unlock(name, password.to_string(), None)
        .expect("unlock");

    let t0 = Instant::now();

    // Inactive → no action
    session.report_lifecycle_state(LifecycleStateDto::Inactive);
    session.drive_tick(t0 + Duration::from_secs(1));
    assert!(session.has_vault(), "inactive: vault still present");

    // Paused → starts 15s grace
    session.report_lifecycle_state(LifecycleStateDto::Paused);
    session.drive_tick(t0 + Duration::from_secs(2));
    assert!(
        session.has_vault(),
        "paused: vault present (grace just started)"
    );

    // 14s into grace — still alive
    session.drive_tick(t0 + Duration::from_secs(16));
    assert!(session.has_vault(), "paused+14s: vault still present");

    // Resumed → cancels grace
    session.report_lifecycle_state(LifecycleStateDto::Resumed);
    session.drive_tick(t0 + Duration::from_secs(17));
    assert!(
        session.has_vault(),
        "resumed: vault still present, grace cancelled"
    );

    // Start grace again with Hidden
    session.report_lifecycle_state(LifecycleStateDto::Hidden);
    session.drive_tick(t0 + Duration::from_secs(18));
    assert!(session.has_vault(), "hidden: grace started");

    // 15s later → grace expires → lock
    session.drive_tick(t0 + Duration::from_secs(33));
    // After Expired, next tick transitions to Locked
    session.drive_tick(t0 + Duration::from_secs(34));

    assert!(!session.has_vault(), "hidden+15s: vault dropped");
    assert!(
        !session.has_credentials(),
        "hidden+15s: credentials dropped"
    );

    let events = recording.drain();
    assert!(
        events.iter().any(|e| matches!(e, LockEvent::Locked)),
        "locked event emitted on lifecycle grace expiry"
    );
}

#[test]
fn lifecycle_detached_locks_immediately() {
    let env = TestEnv::new();
    let name = "test-vault";
    let password = "test-pass";
    let (session, recording) = unlocked_session(&env, name, password);

    session.report_lifecycle_state(LifecycleStateDto::Detached);
    session.drive_tick(Instant::now());

    assert!(!session.has_vault(), "detached: vault dropped immediately");
    assert!(
        !session.has_credentials(),
        "detached: credentials dropped immediately"
    );
    assert!(
        recording
            .drain()
            .iter()
            .any(|e| matches!(e, LockEvent::Locked)),
        "locked event on detach"
    );
}

// ---------------------------------------------------------------------------
// Credentials dropped on every lock path
// ---------------------------------------------------------------------------

#[test]
fn session_credentials_dropped_on_every_lock_path() {
    // Path 1: manual lock
    {
        let env = TestEnv::new();
        let (session, _rec) = unlocked_session(&env, "v1", "p1");
        assert!(session.has_credentials(), "pre-lock: credentials present");
        session.lock_now().expect("manual lock");
        assert!(
            !session.has_credentials(),
            "manual lock: credentials dropped"
        );
    }

    // Path 2: idle auto-lock
    {
        let env = TestEnv::new();
        let vault_path = create_test_vault(&env, "v2", "p2");
        register_vault(&env, "v2", &vault_path);
        let session = AppSession::for_test_with_timeout(env.paths_clone(), Duration::from_secs(2))
            .expect("session");
        session
            .unlock("v2", "p2".to_string(), None)
            .expect("unlock");
        assert!(session.has_credentials(), "pre-idle: credentials present");
        let t0 = Instant::now();
        session.drive_tick(t0); // warm-up: registers unlock activity
        session.drive_tick(t0 + Duration::from_secs(2)); // Active → Expired
        session.drive_tick(t0 + Duration::from_secs(3)); // Expired → Locked
        assert!(!session.has_credentials(), "idle lock: credentials dropped");
    }

    // Path 3: lifecycle (detached)
    {
        let env = TestEnv::new();
        let (session, _rec) = unlocked_session(&env, "v3", "p3");
        assert!(
            session.has_credentials(),
            "pre-lifecycle: credentials present"
        );
        session.report_lifecycle_state(LifecycleStateDto::Detached);
        session.drive_tick(Instant::now());
        assert!(
            !session.has_credentials(),
            "lifecycle lock: credentials dropped"
        );
    }

    // Path 4: shutdown
    {
        let env = TestEnv::new();
        let (session, _rec) = unlocked_session(&env, "v4", "p4");
        assert!(
            session.has_credentials(),
            "pre-shutdown: credentials present"
        );
        session.shutdown();
        assert!(!session.has_credentials(), "shutdown: credentials dropped");
    }
}

// ---------------------------------------------------------------------------
// Multiple sessions per process
// ---------------------------------------------------------------------------

#[test]
fn multiple_sessions_per_process_harden_once() {
    let env1 = TestEnv::new();
    env1.paths().ensure_exists().expect("ensure dir 1");
    let cfg1 = AppInitConfig {
        state_dir: Some(env1.paths().state_dir().to_string_lossy().to_string()),
        config_dir: None,
    };
    let session1 = init_app(&cfg1).expect("session 1 via init_app");

    let env2 = TestEnv::new();
    env2.paths().ensure_exists().expect("ensure dir 2");
    let cfg2 = AppInitConfig {
        state_dir: Some(env2.paths().state_dir().to_string_lossy().to_string()),
        config_dir: None,
    };
    let session2 = init_app(&cfg2).expect("session 2 via init_app");

    assert!(!session1.has_vault(), "session 1 starts locked");
    assert!(!session2.has_vault(), "session 2 starts locked");
    // Both coexist; harden_process ran via OnceLock in both init_app
    // calls (second is a no-op). Success = both construct + both
    // shut down without panicking.
    session2.shutdown();
    session1.shutdown();
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

#[test]
fn shutdown_is_idempotent_and_stops_ticker() {
    let env = TestEnv::new();
    env.paths().ensure_exists().expect("ensure dir");
    let cfg = AppInitConfig {
        state_dir: Some(env.paths().state_dir().to_string_lossy().to_string()),
        config_dir: None,
    };
    let session = init_app(&cfg).expect("init_app with ticker");

    let threads_before = thread_count();
    session.shutdown();
    thread::sleep(Duration::from_millis(50));
    let threads_after_first = thread_count();
    session.shutdown();
    let threads_after_second = thread_count();

    assert!(
        threads_after_first <= threads_before,
        "ticker thread should be joined after first shutdown \
         (before={threads_before}, after={threads_after_first})"
    );
    assert_eq!(
        threads_after_first, threads_after_second,
        "second shutdown should be a no-op"
    );
}

fn thread_count() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Threads:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|n| n.parse().ok())
        })
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Contention (vault_holder binary)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires vault_holder binary: FALACH_VAULT_HOLDER=target/debug/vault_holder (built by falach-core)"]
fn contended_vault_surfaces_holder_pid() {
    let env = TestEnv::new();
    let name = "test-vault";
    let password = "test-pass";
    let vault_path = create_test_vault(&env, name, password);
    register_vault(&env, name, &vault_path);

    // Hold the vault lock from another process
    let held_signal = env.tempdir().join("held");
    let release_signal = env.tempdir().join("release");
    let vault_holder = std::env::var("FALACH_VAULT_HOLDER")
        .unwrap_or_else(|_| "target/debug/vault_holder".to_string());
    let mut holder = std::process::Command::new(&vault_holder)
        .arg("hold")
        .arg(&vault_path)
        .arg(password)
        .arg(&held_signal)
        .arg(&release_signal)
        .spawn()
        .expect("spawn vault_holder");

    // Wait for the holder to acquire the lock
    let deadline = Instant::now() + Duration::from_secs(10);
    while !held_signal.exists() {
        assert!(
            Instant::now() < deadline,
            "vault_holder did not signal 'held' within 10s"
        );
        thread::sleep(Duration::from_millis(50));
    }

    // Now try to unlock — should get Contended
    let session = AppSession::for_test(env.paths_clone()).expect("session");
    let result = session.unlock(name, password.to_string(), None);

    assert!(
        matches!(result, Err(FalachApiError::VaultContended { .. })),
        "expected VaultContended, got: {result:?}"
    );

    // Clean up holder
    std::fs::write(&release_signal, "release").expect("signal release");
    holder.wait().expect("wait for holder exit");
}
