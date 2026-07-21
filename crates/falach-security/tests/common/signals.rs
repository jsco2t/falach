//! Signal-handler test serialization helper.
//!
//! `SIGNAL_GUARD` is a process-global `Mutex<()>` that any test which
//! installs `signal-hook::iterator::Signals`, calls `signal::raise`,
//! or otherwise touches signal disposition **must** acquire at the
//! top of its body. Acquiring the same mutex everywhere prevents two
//! parallel `cargo test` workers in the same binary from racing each
//! other inside the kernel's process-global signal state.
//!
//! Lock at the top of the test; release on drop:
//!
//! ```ignore
//! use crate::common::signals::SIGNAL_GUARD;
//!
//! #[test]
//! fn my_signal_test() {
//!     let _guard = SIGNAL_GUARD.lock().expect("signal guard poisoned");
//!     // ... install handler / raise signal ...
//! }
//! ```
//!
//! Tests that do NOT touch signal disposition do not need this guard.
//!
//! ## When does Phase 1 use it?
//!
//! Phase 1 has no signal-using tests yet — `signal-hook` is deferred
//! to Phase 4 along with its consumers. The helper lands now so
//! Phase 4's tests can `use crate::common::signals::SIGNAL_GUARD`
//! without a forwarding-PR churn. The pattern mirrors vault-core's
//! `EnvGuard` (which landed in T1.x for the same reason).

use std::sync::Mutex;

/// Process-global serialization point for signal-handler-installing
/// tests. See module-level docs for usage.
pub static SIGNAL_GUARD: Mutex<()> = Mutex::new(());
