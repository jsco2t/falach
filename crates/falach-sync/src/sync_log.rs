// Domain acronyms saturate sync_log's docs; see the same note on
// `crate::s3::mod` for the rationale.
#![allow(clippy::doc_markdown)]

//! Structured one-line sync log (design.md §4.9).
//!
//! Replaces the abandoned git transport's commit-message generator. A
//! sync produces a single stderr line summarizing what happened:
//!
//! ```text
//! falach sync: <outcome> [host=<hostname>] [delta=<N>/<M>/<K>] [attempts=<A>] [duration=<D>ms]
//! ```
//!
//! - `<outcome>` is one of `already-in-sync`, `pushed`, `pushed-first-seed`,
//!   `fast-replaced`, `merged`, or `failed`.
//! - `delta=<added>/<modified>/<removed>` is present only for `merged`.
//! - `attempts` is present for `pushed` and `merged` (1 for non-merge).
//! - `host` and `duration` are always present.
//!
//! The CLI / TUI decide when to emit this — to human stderr (this format)
//! or to JSON (`--format json`). This module only owns the
//! string-formatting helper.

use std::fmt::Write;
use std::time::Duration;

use crate::sync::SyncOutcome;

/// Format a one-line sync log per design.md §4.9.
///
/// `hostname` is typically `gethostname::gethostname().to_string_lossy()`
/// at the call site; passed in here so this module stays pure-function
/// (no syscalls, no allocation source other than the format string) and
/// trivially testable.
#[must_use]
pub fn format(outcome: &SyncOutcome, hostname: &str, duration: Duration) -> String {
    let outcome_name = match outcome {
        SyncOutcome::AlreadyInSync => "already-in-sync",
        SyncOutcome::Pushed {
            is_first_seed: true,
        } => "pushed-first-seed",
        SyncOutcome::Pushed { .. } => "pushed",
        SyncOutcome::FastReplaced => "fast-replaced",
        SyncOutcome::Merged { .. } => "merged",
    };

    let mut line = format!("falach sync: {outcome_name} [host={hostname}]");

    // `write!(&mut String, ...)` cannot fail (the `fmt::Write` impl on
    // `String` panics on OOM, not returns an error). Drop the `Result`
    // explicitly to avoid `must_use` noise.
    if let SyncOutcome::Merged { delta, attempts } = outcome {
        let _ = write!(
            line,
            " [delta={}/{}/{}]",
            delta.added.len(),
            delta.modified.len(),
            delta.removed.len()
        );
        let _ = write!(line, " [attempts={attempts}]");
    } else if let SyncOutcome::Pushed { .. } = outcome {
        // FR-042 / impl-plan §4.9: attempts is always 1 for non-merge
        // outcomes. Included for parser consistency.
        line.push_str(" [attempts=1]");
    }

    let ms = duration.as_millis();
    let _ = write!(line, " [duration={ms}ms]");
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge::EntryDelta;
    use falach_core::Uuid;

    fn fake_uuid(n: u8) -> Uuid {
        let mut bytes = [0u8; 16];
        bytes[15] = n;
        Uuid::from_bytes(bytes)
    }

    // -- TC-LOG-001 ---------------------------------------------------------
    #[test]
    fn format_already_in_sync_minimal_line() {
        let line = format(
            &SyncOutcome::AlreadyInSync,
            "host-foo",
            Duration::from_millis(12),
        );
        assert_eq!(
            line,
            "falach sync: already-in-sync [host=host-foo] [duration=12ms]"
        );
    }

    // -- TC-LOG-002 ---------------------------------------------------------
    #[test]
    fn format_merged_includes_delta_and_attempts() {
        let delta = EntryDelta {
            added: vec![fake_uuid(1), fake_uuid(2)],
            modified: vec![fake_uuid(3)],
            removed: vec![],
        };
        let outcome = SyncOutcome::Merged { delta, attempts: 2 };
        let line = format(&outcome, "host-bar", Duration::from_millis(345));
        assert!(line.contains("merged"), "got: {line}");
        assert!(line.contains("[delta=2/1/0]"), "got: {line}");
        assert!(line.contains("[attempts=2]"), "got: {line}");
        assert!(line.contains("[duration=345ms]"), "got: {line}");
    }

    // -- TC-LOG-003 ---------------------------------------------------------
    #[test]
    fn format_pushed_first_seed_distinguishes() {
        let line = format(
            &SyncOutcome::Pushed {
                is_first_seed: true,
            },
            "host-baz",
            Duration::from_millis(50),
        );
        assert!(
            line.contains("pushed-first-seed"),
            "first-seed distinguished from steady-state pushed; got: {line}"
        );
        let line_steady = format(
            &SyncOutcome::Pushed {
                is_first_seed: false,
            },
            "host-baz",
            Duration::from_millis(50),
        );
        assert!(line_steady.contains("falach sync: pushed "));
        assert!(!line_steady.contains("first-seed"));
    }

    // -- TC-LOG-004 ---------------------------------------------------------
    #[test]
    fn format_fast_replaced_omits_delta() {
        let line = format(
            &SyncOutcome::FastReplaced,
            "host-qux",
            Duration::from_millis(99),
        );
        assert!(line.contains("fast-replaced"), "got: {line}");
        assert!(
            !line.contains("delta="),
            "no delta on FastReplaced; got: {line}"
        );
        // FastReplaced is not a Pushed/Merged outcome — no attempts field
        // (steady-state read-only behavior; consistent with AlreadyInSync).
        assert!(
            !line.contains("attempts="),
            "no attempts on FastReplaced; got: {line}"
        );
    }
}
