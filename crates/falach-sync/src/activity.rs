//! Activity-pinger wrapper (design §2.2.11) — **deferred to the orchestration
//! phase (T5.2/T5.3)**.
//!
//! This wrapper is meant to adapt an optional
//! `falach_security::AutoLockController` into a throttled "register activity
//! during long ops" helper, pinging at every fetch boundary and every group
//! boundary in a merge so a long sync doesn't trip idle auto-lock.
//!
//! It is intentionally empty in the Phase 1 scaffold. The real
//! `AutoLockController::register_activity(&mut self, now)` takes `&mut self`,
//! which contradicts the design sketch's shared `Option<&AutoLockController>`
//! shape. Committing the controller's borrow/ownership shape — and pulling in
//! the `falach-security` dependency it implies — is left until the pinger is
//! actually wired, so the public [`crate::SyncOptions`] type is not locked to
//! a shape the live API rejects. See `crate::sync` for the matching note.
