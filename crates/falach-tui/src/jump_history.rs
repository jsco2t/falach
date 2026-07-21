//! Session-only jump history (T4.4, design §2.2.8 / D-8).
//!
//! A browser-style back/forward stack over visited nodes (entries *and*
//! groups). It is **session-only**: capped at [`JUMP_HISTORY_CAP`], never
//! persisted to `tui.toml`, and cleared on lock (like all other view state), so
//! it carries no zeroize obligations — it holds UUIDs, not secrets.
//!
//! The visited trail lives in `back`, most-recent last; the currently-shown
//! node is the trail head. [`JumpHistory::back`]/[`JumpHistory::forward`] take
//! the live selection as `current` so a selection moved by arrow keys (which do
//! not push) can never desync the walk.

use falach_core::Uuid;

/// Maximum entries retained in the jump-history trail (D-8). A named constant,
/// not a config knob (resolution A-4 — no knob sprawl). When the trail exceeds
/// this, the oldest entries are evicted from the front.
pub(crate) const JUMP_HISTORY_CAP: usize = 100;

/// Session-only back/forward history over visited tree nodes.
#[derive(Debug, Default)]
pub(crate) struct JumpHistory {
    /// Visited trail, oldest first; the last element is the current node.
    back: Vec<Uuid>,
    /// Nodes stepped back *from*, available to step forward into (nearest last).
    forward: Vec<Uuid>,
}

impl JumpHistory {
    /// Record a visit to `id`. Consecutive duplicates collapse (re-opening the
    /// same node is not a new history step); any pending forward trail is
    /// cleared (a new visit diverges from the old forward path); the trail is
    /// capped at [`JUMP_HISTORY_CAP`] by evicting the oldest entries.
    pub(crate) fn push(&mut self, id: Uuid) {
        if self.back.last() == Some(&id) {
            return;
        }
        self.forward.clear();
        self.back.push(id);
        self.cap();
    }

    /// Step back from `current`, returning the previous node (which the caller
    /// then selects). `None` when there is no earlier node.
    pub(crate) fn back(&mut self, current: Uuid) -> Option<Uuid> {
        // Keep the trail head aligned with the live selection: if the selection
        // moved without a push, re-anchor on it before stepping back.
        if self.back.last() != Some(&current) {
            self.push(current);
        }
        if self.back.len() < 2 {
            return None;
        }
        let left = self.back.pop().expect("len checked >= 2");
        self.forward.push(left);
        self.back.last().copied()
    }

    /// Step forward from `current`, returning the next node, or `None` when the
    /// forward trail is empty.
    pub(crate) fn forward(&mut self, current: Uuid) -> Option<Uuid> {
        let next = self.forward.pop()?;
        if self.back.last() != Some(&current) {
            self.back.push(current);
        }
        self.back.push(next);
        self.cap();
        Some(next)
    }

    /// Clear the whole history (called on lock — D-8).
    pub(crate) fn clear(&mut self) {
        self.back.clear();
        self.forward.clear();
    }

    /// Evict oldest trail entries beyond the cap.
    fn cap(&mut self) {
        if self.back.len() > JUMP_HISTORY_CAP {
            let excess = self.back.len() - JUMP_HISTORY_CAP;
            self.back.drain(0..excess);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jump_history_push_dedupe_cap_and_walk() {
        let a = Uuid::new_v4();
        let d = Uuid::new_v4();
        let f = Uuid::new_v4();
        let mut hist = JumpHistory::default();
        hist.push(a);
        hist.push(d);
        hist.push(d); // consecutive dup collapses
        hist.push(f);

        // Walk back: F → D → A.
        assert_eq!(hist.back(f), Some(d));
        assert_eq!(hist.back(d), Some(a));
        assert_eq!(hist.back(a), None, "no earlier node than A");
        // Walk forward: A → D.
        assert_eq!(hist.forward(a), Some(d));

        // Cap eviction: 105 distinct pushes retain only the most recent 100, so
        // the oldest is no longer reachable by walking back.
        let mut hist = JumpHistory::default();
        let ids: Vec<Uuid> = (0..105).map(|_| Uuid::new_v4()).collect();
        for id in &ids {
            hist.push(*id);
        }
        let mut current = *ids.last().unwrap();
        let mut steps = 0;
        while let Some(prev) = hist.back(current) {
            current = prev;
            steps += 1;
        }
        assert_eq!(steps, 99, "trail capped at 100 nodes → 99 back-steps");
        assert_eq!(current, ids[5], "oldest 5 nodes evicted");
    }

    #[test]
    fn jump_clears_forward_on_new_visit() {
        let a = Uuid::new_v4();
        let d = Uuid::new_v4();
        let f = Uuid::new_v4();
        let x = Uuid::new_v4();
        let mut hist = JumpHistory::default();
        hist.push(a);
        hist.push(d);
        hist.push(f);
        assert_eq!(hist.back(f), Some(d)); // now at D, forward = [F]
        hist.push(x); // a new visit diverges → forward cleared
        assert_eq!(hist.forward(x), None, "new visit clears the forward trail");
    }
}
