//! Shared test helpers for `falach-security`.
//!
//! Phase 1 landed `signals`. Phase 2 adds `clock` (the `FakeClock`
//! used by `tests/us_051_idle_auto_lock.rs`). Phase 3 will add a
//! `fixtures` module with `FakeClipboardBackend`.

#![allow(dead_code)] // not all helpers used by every integration test

pub mod clock;
pub mod signals;
