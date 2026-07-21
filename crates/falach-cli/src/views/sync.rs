//! `falach sync` JSON-schema contract.
//!
//! ## Schema stability
//!
//! `outcome` is a stable kebab-case tag; `first_seed` is present only for
//! `pushed`, and `delta`/`attempts` only for `merged` (additive-optional,
//! `skip_serializing_if`). The merge delta is reported as **counts**, never
//! entry UUIDs — the JSON output carries no entry identity or secret
//! material.

use serde::Serialize;

use falach_sync::SyncOutcome;

/// JSON output for `falach sync`.
#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct SyncView {
    /// Stable outcome tag: `already-in-sync` / `pushed` / `fast-replaced`
    /// / `merged` (or `unknown` for a future `#[non_exhaustive]` variant).
    pub outcome: &'static str,
    /// Present only for `pushed`: `true` on the first-ever seed of an empty
    /// remote, `false` for a steady-state push.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seed: Option<bool>,
    /// Present only for `merged`: how the local database changed (counts).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<DeltaView>,
    /// Present only for `merged`: conditional-PUT attempts consumed (≥1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<usize>,
}

/// Merge delta as counts (never entry UUIDs).
#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct DeltaView {
    /// Entries folded in from the remote.
    pub added: usize,
    /// Entries the remote won on a contested edit.
    pub modified: usize,
    /// Entries removed via a remote deletion tombstone.
    pub removed: usize,
}

impl From<&SyncOutcome> for SyncView {
    fn from(outcome: &SyncOutcome) -> Self {
        match outcome {
            SyncOutcome::AlreadyInSync => Self {
                outcome: "already-in-sync",
                first_seed: None,
                delta: None,
                attempts: None,
            },
            SyncOutcome::Pushed { is_first_seed } => Self {
                outcome: "pushed",
                first_seed: Some(*is_first_seed),
                delta: None,
                attempts: None,
            },
            SyncOutcome::FastReplaced => Self {
                outcome: "fast-replaced",
                first_seed: None,
                delta: None,
                attempts: None,
            },
            SyncOutcome::Merged { delta, attempts } => Self {
                outcome: "merged",
                first_seed: None,
                delta: Some(DeltaView {
                    added: delta.added.len(),
                    modified: delta.modified.len(),
                    removed: delta.removed.len(),
                }),
                attempts: Some(*attempts),
            },
            // `SyncOutcome` is `#[non_exhaustive]`; a future variant renders
            // as a safe generic tag until it is wired explicitly.
            _ => Self {
                outcome: "unknown",
                first_seed: None,
                delta: None,
                attempts: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use falach_core::Uuid;
    use falach_sync::EntryDelta;
    use serde_json::{json, Value};

    fn json_of<V: Serialize>(view: &V) -> Value {
        serde_json::from_str(&serde_json::to_string(view).expect("serialize")).expect("parse")
    }

    /// `n` UUIDs — only the count matters for the delta view, so nil UUIDs
    /// (no `v4` feature needed) are fine.
    fn uuids(n: usize) -> Vec<Uuid> {
        vec![Uuid::nil(); n]
    }

    #[test]
    fn sync_view_covers_every_outcome_variant() {
        // AlreadyInSync
        let v = SyncView::from(&SyncOutcome::AlreadyInSync);
        assert_eq!(v.outcome, "already-in-sync");
        assert!(v.first_seed.is_none() && v.delta.is_none() && v.attempts.is_none());

        // Pushed (both first-seed and steady-state)
        let v = SyncView::from(&SyncOutcome::Pushed {
            is_first_seed: true,
        });
        assert_eq!(v.outcome, "pushed");
        assert_eq!(v.first_seed, Some(true));
        let v = SyncView::from(&SyncOutcome::Pushed {
            is_first_seed: false,
        });
        assert_eq!(v.first_seed, Some(false));

        // FastReplaced
        let v = SyncView::from(&SyncOutcome::FastReplaced);
        assert_eq!(v.outcome, "fast-replaced");

        // Merged — delta carries COUNTS (added/modified/removed) + attempts.
        let v = SyncView::from(&SyncOutcome::Merged {
            delta: EntryDelta {
                added: uuids(2),
                modified: uuids(1),
                removed: uuids(3),
            },
            attempts: 2,
        });
        assert_eq!(v.outcome, "merged");
        assert_eq!(
            v.delta,
            Some(DeltaView {
                added: 2,
                modified: 1,
                removed: 3,
            })
        );
        assert_eq!(v.attempts, Some(2));
    }

    #[test]
    fn sync_view_serializes_to_expected_json_keys() {
        // already-in-sync omits the optional fields entirely.
        let v = SyncView::from(&SyncOutcome::AlreadyInSync);
        assert_eq!(json_of(&v), json!({ "outcome": "already-in-sync" }));

        // pushed carries first_seed only.
        let v = SyncView::from(&SyncOutcome::Pushed {
            is_first_seed: true,
        });
        assert_eq!(
            json_of(&v),
            json!({ "outcome": "pushed", "first_seed": true })
        );

        // fast-replaced carries no optional fields.
        let v = SyncView::from(&SyncOutcome::FastReplaced);
        assert_eq!(json_of(&v), json!({ "outcome": "fast-replaced" }));

        // merged carries delta counts + attempts.
        let v = SyncView::from(&SyncOutcome::Merged {
            delta: EntryDelta {
                added: uuids(1),
                modified: uuids(0),
                removed: uuids(2),
            },
            attempts: 1,
        });
        assert_eq!(
            json_of(&v),
            json!({
                "outcome": "merged",
                "delta": { "added": 1, "modified": 0, "removed": 2 },
                "attempts": 1,
            })
        );
    }
}
