//! US-051 — Idle auto-lock.
//!
//! Drives [`AutoLockController`] through a frontend-shaped call
//! sequence using a [`FakeClock`] (deterministic time). The first two
//! cases exercise the everyday lifecycle (`Active → Expired → Locked`
//! and re-entry via `unlock`); the last two cases load TOML fixtures
//! through `falach_core::VaultRegistry` and exercise
//! `vault_lock::VaultLockConfig::from_extra` (Phase 4 T4.2).

mod common;

use std::time::{Duration, Instant};

use falach_core::{FalachPaths, VaultRegistry};
use falach_security::{
    AutoLockConfig, AutoLockController, Clock, LockState, VaultLockConfig, DEFAULT_IDLE_TIMEOUT,
};
use tempfile::TempDir;

use common::clock::FakeClock;

/// Stage a `vaults.toml` fixture into a fresh tempdir and load a
/// [`VaultRegistry`] rooted there. Returns the tempdir (held by the
/// caller so the directory survives the test) and the registry.
fn load_registry_from_fixture(fixture: &str) -> (TempDir, VaultRegistry) {
    let tmp = TempDir::new().expect("tempdir creation");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&state_dir).expect("mkdir -p state");
    std::fs::write(state_dir.join("vaults.toml"), fixture).expect("write vaults.toml fixture");
    let paths = FalachPaths::with_state_dir(state_dir);
    let registry = VaultRegistry::load(paths).expect("load fixture registry");
    (tmp, registry)
}

/// US-051 AC #1: the controller transitions
/// `Active → Expired → Locked` at the configured timeout.
#[test]
fn controller_locks_at_configured_timeout_via_fake_clock() {
    let clock = FakeClock::new(Instant::now());
    let mut controller = AutoLockController::new(AutoLockConfig {
        idle_timeout: Duration::from_secs(1),
    })
    .expect("1-second timeout is valid");

    // t = 0: record initial activity.
    controller.register_activity(clock.now());
    assert_eq!(
        controller.tick(clock.now()),
        LockState::Active,
        "freshly registered, before timeout: Active"
    );

    // t = 999ms: still inside the deadline.
    clock.advance(Duration::from_millis(999));
    assert_eq!(
        controller.tick(clock.now()),
        LockState::Active,
        "1ms inside the deadline: Active"
    );

    // t = 1000ms: at-deadline boundary — one-tick warning state.
    clock.advance(Duration::from_millis(1));
    assert_eq!(
        controller.tick(clock.now()),
        LockState::Expired,
        "at deadline: Expired (one-tick warning)"
    );

    // t = 1001ms: next tick after Expired transitions to Locked.
    clock.advance(Duration::from_millis(1));
    assert_eq!(
        controller.tick(clock.now()),
        LockState::Locked,
        "tick after Expired: Locked"
    );
}

/// US-051 AC #2: `unlock(now)` re-arms the controller; the next
/// idle cycle behaves identically to the first.
#[test]
fn controller_unlocks_and_re_arms() {
    let clock = FakeClock::new(Instant::now());
    let mut controller = AutoLockController::new(AutoLockConfig {
        idle_timeout: Duration::from_secs(1),
    })
    .expect("valid");

    // Drive into Locked.
    controller.register_activity(clock.now());
    clock.advance(Duration::from_secs(1));
    assert_eq!(controller.tick(clock.now()), LockState::Expired);
    clock.advance(Duration::from_millis(1));
    assert_eq!(controller.tick(clock.now()), LockState::Locked);

    // Re-unlock at t = t1 (whatever t1 is — the controller resets
    // its deadline based on the supplied `now`).
    let t1 = clock.now();
    controller.unlock(t1);
    assert_eq!(controller.state(), LockState::Active, "unlock → Active");

    // Cycle again: 500ms still Active, 1000ms Expired, 1001ms Locked.
    clock.advance(Duration::from_millis(500));
    assert_eq!(
        controller.tick(clock.now()),
        LockState::Active,
        "re-armed cycle: 500ms in, still Active"
    );

    clock.advance(Duration::from_millis(500));
    assert_eq!(
        controller.tick(clock.now()),
        LockState::Expired,
        "re-armed cycle: at deadline, Expired"
    );

    clock.advance(Duration::from_millis(1));
    assert_eq!(
        controller.tick(clock.now()),
        LockState::Locked,
        "re-armed cycle: tick after Expired, Locked"
    );
}

// ---------------------------------------------------------------------------
// Per-vault-override cases — added in Phase 2 with `unimplemented!`
// bodies; Phase 4 T4.2 wires them up against `falach_core::VaultRegistry`
// + `vault_lock::VaultLockConfig::from_extra`.
// ---------------------------------------------------------------------------

/// US-051 AC #3: a `[vault.lock] idle_timeout_seconds = 30` override
/// in `vaults.toml` is honoured — the controller locks at 30s, not
/// the default 600s. Fixture: `tests/fixtures/vaults_with_lock_override.toml`.
#[test]
fn per_vault_override_from_vaults_toml_is_honored() {
    // Load the fixture through the real `VaultRegistry` so we exercise
    // the production read path end-to-end.
    let fixture = include_str!("fixtures/vaults_with_lock_override.toml");
    let (_tmp, registry) = load_registry_from_fixture(fixture);

    let vault = registry
        .get("personal")
        .expect("fixture registers a `personal` vault");
    let lock_cfg = VaultLockConfig::from_extra(&vault.extra)
        .expect("override sub-table should parse")
        .expect("fixture sets [vault.lock]");
    assert_eq!(
        lock_cfg.idle_timeout_seconds, 30,
        "fixture override should arrive verbatim",
    );

    // Drive a controller built from the override and confirm it locks
    // at 30s, not at the default 600s.
    let auto_lock_cfg = lock_cfg
        .to_auto_lock_config()
        .expect("30s is a valid timeout");
    let clock = FakeClock::new(Instant::now());
    let mut controller = AutoLockController::new(auto_lock_cfg).expect("valid controller");
    controller.register_activity(clock.now());

    // At t = 29s the controller is still Active.
    clock.advance(Duration::from_secs(29));
    assert_eq!(
        controller.tick(clock.now()),
        LockState::Active,
        "29s in (1s before override deadline): Active",
    );
    // At t = 30s the controller hits the override deadline — Expired.
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        controller.tick(clock.now()),
        LockState::Expired,
        "at 30s override deadline: Expired",
    );
    // The next tick locks.
    clock.advance(Duration::from_millis(1));
    assert_eq!(
        controller.tick(clock.now()),
        LockState::Locked,
        "tick after Expired: Locked",
    );
}

/// US-051 AC #4: a registered vault with NO `[vault.lock]` section
/// falls back to [`DEFAULT_IDLE_TIMEOUT`] (600s). Fixture:
/// `tests/fixtures/vaults_minimal.toml`.
#[test]
fn per_vault_override_absent_falls_back_to_default() {
    let fixture = include_str!("fixtures/vaults_minimal.toml");
    let (_tmp, registry) = load_registry_from_fixture(fixture);

    let vault = registry
        .get("personal")
        .expect("fixture registers a `personal` vault");
    let lock_cfg =
        VaultLockConfig::from_extra(&vault.extra).expect("absent sub-table should be Ok(None)");
    assert!(
        lock_cfg.is_none(),
        "minimal fixture has no [vault.lock]; from_extra must return None",
    );

    // The fallback path: the frontend constructs the controller with
    // `AutoLockConfig::default()`. Pin the default to 600s here so a
    // regression in `DEFAULT_IDLE_TIMEOUT` would surface loudly.
    assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(600));
    let controller = AutoLockController::new(AutoLockConfig::default()).expect("valid");
    let clock = FakeClock::new(Instant::now());
    assert_eq!(
        controller.state(),
        LockState::Active,
        "freshly constructed controller is Active",
    );
    // Cheap sanity: the controller is still Active well past 30s
    // (which would be the override deadline if any override leaked
    // through).
    let mut controller = controller;
    controller.register_activity(clock.now());
    clock.advance(Duration::from_secs(60));
    assert_eq!(
        controller.tick(clock.now()),
        LockState::Active,
        "60s in, well past the (absent) 30s override: still Active",
    );
}
