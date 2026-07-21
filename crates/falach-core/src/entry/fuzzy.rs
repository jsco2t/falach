//! Hand-rolled fzf-v2-style fuzzy matcher (T1.4).
//!
//! [`fuzzy_match`] scores a `needle` against a `haystack` and, on a match,
//! returns the total [`FuzzyMatch::score`] plus the **character** positions of
//! the matched needle characters ([`FuzzyMatch::indices`]) so a renderer can
//! highlight them. [`fuzzy_match_terms`] ANDs space-separated terms.
//!
//! We hand-roll rather than depend on `nucleo`/`nucleo-matcher`, which are
//! MPL-2.0 and forbidden by the supply-chain policy (`deny.toml`; see
//! `features/tui-enhancements/research/study-television.md`). The scoring model
//! follows fzf-v2 (github.com/junegunn/fzf, `src/algo/algo.go`): a per-position
//! word-boundary / camelCase / prefix bonus, a consecutive-run bonus, and a
//! gap-open / gap-extend penalty. The single [`scoring`] constant block is the
//! one place to tune ranking — the `GOLDEN_PAIRS` test locks each property.
//!
//! ## Contracts
//!
//! - **Char positions, not bytes.** `indices` are positions into
//!   `haystack.chars()`, matching how the TUI renderer iterates. This is the #1
//!   latent bug source in fuzzy matchers; the `unicode_char_indices` test pins
//!   it.
//! - **Smartcase, per character.** A lowercase needle character matches
//!   case-insensitively; an uppercase needle character matches only that exact
//!   uppercase character (fzf behaviour).
//! - **Empty needle is a match.** `fuzzy_match("", h)` returns
//!   `Some(FuzzyMatch { score: 0, indices: [] })` — the browse-mode contract the
//!   search overlay (T4.2) relies on, where an empty query lists everything.

/// Scoring constants (fzf-v2 model). One block so tuning is a one-line diff; the
/// `GOLDEN_PAIRS` test names the property each governs.
mod scoring {
    /// Base reward for a matched character.
    pub const SCORE_MATCH: i32 = 16;
    /// Penalty for opening a gap (the first skipped character).
    pub const SCORE_GAP_START: i32 = -3;
    /// Penalty for each additional skipped character in a gap.
    pub const SCORE_GAP_EXT: i32 = -1;
    /// Bonus for a match at a word boundary (a character following a
    /// non-alphanumeric delimiter — space, `-`, `_`, `/`, `.`, `:`, … — or the
    /// start of the string).
    pub const BONUS_BOUNDARY: i32 = 8;
    /// Bonus for a `lower→Upper` camelCase transition.
    pub const BONUS_CAMEL: i32 = 7;
    /// Bonus for a match immediately following the previous match (a run).
    pub const BONUS_CONSECUTIVE: i32 = 4;
    /// The start-of-string boundary bonus is doubled (a leading match is the
    /// strongest signal).
    pub const BONUS_FIRST_CHAR_MULT: i32 = 2;
}

/// A negative sentinel for "unreachable DP cell". Half of `i32::MIN` so adding a
/// bounded penalty can never overflow.
const UNREACHABLE: i32 = i32::MIN / 2;

/// The result of a successful fuzzy match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzyMatch {
    /// Total match score. Higher is a better match. May be negative for a poor
    /// (heavily-gapped) but still-valid subsequence match.
    pub score: i32,
    /// Character positions (into `haystack.chars()`) of the matched needle
    /// characters, strictly increasing.
    pub indices: Vec<u32>,
}

/// Does needle character `n` match haystack character `h` under the per-char
/// smartcase rule? An uppercase needle char is case-sensitive; anything else
/// folds case.
fn char_matches(n: char, h: char) -> bool {
    if n.is_uppercase() {
        n == h
    } else {
        n == h || n.to_lowercase().eq(h.to_lowercase())
    }
}

/// The position bonus for matching at haystack index `j` given the previous
/// haystack character `prev` (`None` at the start of the string).
fn position_bonus(prev: Option<char>, cur: char) -> i32 {
    match prev {
        // Start of string: a boundary, doubled.
        None => scoring::BONUS_BOUNDARY * scoring::BONUS_FIRST_CHAR_MULT,
        Some(p) => {
            if !p.is_alphanumeric() {
                // Following a delimiter (space, `-`, `/`, `.`, …): word boundary.
                scoring::BONUS_BOUNDARY
            } else if p.is_lowercase() && cur.is_uppercase() {
                scoring::BONUS_CAMEL
            } else {
                0
            }
        }
    }
}

/// Cheap subsequence pre-check under the smartcase rule: is every needle
/// character found, in order, in the haystack? Bails out of the DP for the
/// common non-matching case.
fn is_subsequence(needle: &[char], haystack: &[char]) -> bool {
    let mut ni = 0;
    for &h in haystack {
        if ni == needle.len() {
            break;
        }
        if char_matches(needle[ni], h) {
            ni += 1;
        }
    }
    ni == needle.len()
}

/// Score `needle` against `haystack`, returning the score and matched character
/// positions, or `None` when `needle` is not a (smartcase) subsequence of
/// `haystack`. An empty needle matches with score `0` and no indices.
///
/// Runs an `O(n·m)` dynamic program (n = haystack chars, m = needle chars) with
/// traceback — the fields it scores are short (titles/URLs < ~200 chars), so the
/// simple full-matrix form is expected to remain within the NFR-002 budget;
/// T4.1 adds the 5,000-entry benchmark gate that verifies it end to end.
pub fn fuzzy_match(needle: &str, haystack: &str) -> Option<FuzzyMatch> {
    let n_chars: Vec<char> = needle.chars().collect();
    if n_chars.is_empty() {
        return Some(FuzzyMatch {
            score: 0,
            indices: Vec::new(),
        });
    }
    let h_chars: Vec<char> = haystack.chars().collect();
    if !is_subsequence(&n_chars, &h_chars) {
        return None;
    }

    let m = n_chars.len();
    let n = h_chars.len();

    // Per-position boundary/camel bonus, computed once.
    let bonus: Vec<i32> = (0..n)
        .map(|j| {
            let prev = if j == 0 { None } else { Some(h_chars[j - 1]) };
            position_bonus(prev, h_chars[j])
        })
        .collect();

    // dp[i][j] = best total score matching needle[0..=i] with needle[i] placed
    // exactly at haystack position j (UNREACHABLE if that placement is
    // impossible). parent[i][j] = the haystack position of needle[i-1] in the
    // best such alignment (for index traceback).
    let mut dp = vec![vec![UNREACHABLE; n]; m];
    let mut parent = vec![vec![usize::MAX; n]; m];

    for i in 0..m {
        // For non-consecutive transitions into column `j`, the score is:
        //
        // prev[k] + GAP_START + GAP_EXT * (j - k - 2)
        //
        // The `j` portion is constant for the column, so retain the best
        // `prev[k] - GAP_EXT * k` seen through `j - 2`. This avoids rescanning
        // the whole prior row for every cell and keeps the DP O(m*n).
        let mut best_gap_base = UNREACHABLE;
        let mut best_gap_k = usize::MAX;
        for j in i..n {
            if i > 0 && j >= 2 {
                let k = j - 2;
                let prev_score = dp[i - 1][k];
                if prev_score != UNREACHABLE {
                    let k_i32 = i32::try_from(k).unwrap_or(i32::MAX);
                    let gap_base = prev_score - scoring::SCORE_GAP_EXT * k_i32;
                    if gap_base > best_gap_base {
                        best_gap_base = gap_base;
                        best_gap_k = k;
                    }
                }
            }
            if !char_matches(n_chars[i], h_chars[j]) {
                continue;
            }
            if i == 0 {
                // No leading-gap penalty before the first matched character
                // (fzf rewards a prefix via `bonus`, does not penalise the
                // skipped prefix).
                dp[i][j] = scoring::SCORE_MATCH + bonus[j];
            } else {
                let mut best = UNREACHABLE;
                let mut best_k = usize::MAX;

                if best_gap_base != UNREACHABLE {
                    let j = i32::try_from(j).unwrap_or(i32::MAX);
                    best =
                        best_gap_base + scoring::SCORE_GAP_START + scoring::SCORE_GAP_EXT * (j - 2);
                    best_k = best_gap_k;
                }

                // Check the adjacent predecessor last. The old ascending
                // predecessor scan preferred an earlier gapped alignment on an
                // exact tie, so only a strictly better consecutive score wins.
                if j > 0 {
                    let prev_score = dp[i - 1][j - 1];
                    let consecutive = prev_score + scoring::BONUS_CONSECUTIVE;
                    if prev_score != UNREACHABLE && consecutive > best {
                        best = consecutive;
                        best_k = j - 1;
                    }
                }
                if best > UNREACHABLE {
                    dp[i][j] = best + scoring::SCORE_MATCH + bonus[j];
                    parent[i][j] = best_k;
                }
            }
        }
    }

    // Best final placement of the last needle character: scan its row's tail.
    let mut best_j = usize::MAX;
    let mut best_score = UNREACHABLE;
    for (offset, &score) in dp[m - 1][(m - 1)..].iter().enumerate() {
        if score > best_score {
            best_score = score;
            best_j = (m - 1) + offset;
        }
    }
    if best_j == usize::MAX {
        return None;
    }

    // Trace back to recover the matched positions (char positions → u32; a
    // haystack cannot exceed u32::MAX chars for any realistic field).
    let mut indices = vec![0u32; m];
    let mut j = best_j;
    for i in (0..m).rev() {
        indices[i] = u32::try_from(j).unwrap_or(u32::MAX);
        if i > 0 {
            j = parent[i][j];
        }
    }

    Some(FuzzyMatch {
        score: best_score,
        indices,
    })
}

/// Match a whitespace-separated `query` where **every** term must match
/// (`AND`), summing the term scores. Matched indices from all terms are merged,
/// deduplicated, and sorted. An empty (or all-whitespace) query matches with
/// score `0` and no indices — the browse-mode contract.
///
/// Exposed here (not only in the caller) because the command palette (T2.3) also
/// needs multi-term matching over command names.
pub fn fuzzy_match_terms(query: &str, haystack: &str) -> Option<FuzzyMatch> {
    let mut total = 0;
    let mut indices: Vec<u32> = Vec::new();
    let mut any = false;
    for term in query.split_whitespace() {
        any = true;
        let m = fuzzy_match(term, haystack)?;
        total += m.score;
        indices.extend(m.indices);
    }
    if !any {
        // Empty / whitespace-only query: browse mode.
        return Some(FuzzyMatch {
            score: 0,
            indices: Vec::new(),
        });
    }
    indices.sort_unstable();
    indices.dedup();
    Some(FuzzyMatch {
        score: total,
        indices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic LCG (no `rand`/`proptest` dependency — project rule). The
    /// multiplier/increment are the well-known Knuth MMIX constants.
    fn lcg(seed: u64) -> impl Iterator<Item = u64> {
        let mut state = seed;
        std::iter::from_fn(move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            Some(state)
        })
    }

    /// Straightforward predecessor-scanning recurrence retained as a test
    /// oracle for the optimized prefix-best implementation.
    fn fuzzy_match_reference(needle: &str, haystack: &str) -> Option<FuzzyMatch> {
        let n_chars: Vec<char> = needle.chars().collect();
        if n_chars.is_empty() {
            return Some(FuzzyMatch {
                score: 0,
                indices: Vec::new(),
            });
        }
        let h_chars: Vec<char> = haystack.chars().collect();
        if !is_subsequence(&n_chars, &h_chars) {
            return None;
        }
        let m = n_chars.len();
        let n = h_chars.len();
        let bonus: Vec<i32> = (0..n)
            .map(|j| position_bonus((j > 0).then(|| h_chars[j - 1]), h_chars[j]))
            .collect();
        let mut dp = vec![vec![UNREACHABLE; n]; m];
        let mut parent = vec![vec![usize::MAX; n]; m];
        for i in 0..m {
            for j in i..n {
                if !char_matches(n_chars[i], h_chars[j]) {
                    continue;
                }
                if i == 0 {
                    dp[i][j] = scoring::SCORE_MATCH + bonus[j];
                    continue;
                }
                let mut best = UNREACHABLE;
                let mut best_k = usize::MAX;
                for (offset, &prev_score) in dp[i - 1][(i - 1)..j].iter().enumerate() {
                    if prev_score == UNREACHABLE {
                        continue;
                    }
                    let k = (i - 1) + offset;
                    let step = if k == j - 1 {
                        scoring::BONUS_CONSECUTIVE
                    } else {
                        let skipped = i32::try_from(j - k - 1).unwrap_or(i32::MAX);
                        scoring::SCORE_GAP_START + scoring::SCORE_GAP_EXT * (skipped - 1)
                    };
                    let candidate = prev_score + step;
                    if candidate > best {
                        best = candidate;
                        best_k = k;
                    }
                }
                if best > UNREACHABLE {
                    dp[i][j] = best + scoring::SCORE_MATCH + bonus[j];
                    parent[i][j] = best_k;
                }
            }
        }
        let mut best_j = usize::MAX;
        let mut best_score = UNREACHABLE;
        for (j, &score) in dp[m - 1].iter().enumerate().skip(m - 1) {
            if score > best_score {
                best_j = j;
                best_score = score;
            }
        }
        if best_j == usize::MAX {
            return None;
        }
        let mut indices = vec![0u32; m];
        let mut j = best_j;
        for i in (0..m).rev() {
            indices[i] = u32::try_from(j).unwrap_or(u32::MAX);
            if i > 0 {
                j = parent[i][j];
            }
        }
        Some(FuzzyMatch {
            score: best_score,
            indices,
        })
    }

    /// `(query, better, worse)`: `better` must strictly outscore `worse`. Each
    /// row isolates one scoring property.
    const GOLDEN_PAIRS: &[(&str, &str, &str)] = &[
        // camelCase / prefix boundary beats a scattered interior match.
        ("git", "GitHub", "digit"),
        // Prefix match beats a later, delimiter-separated match.
        ("us", "user", "sudo su"),
        // Consecutive run beats a gapped match (no boundary confusion).
        ("ab", "xabz", "xaybz"),
        // Word-boundary chain (start + delimiter) beats interior consecutive.
        ("md", "my-dir", "amdx"),
        // Prefix beats interior even when both are fully consecutive.
        ("cat", "category", "polecat"),
        // Smaller gap beats a larger gap.
        ("ac", "abc", "axxxxc"),
        // camelCase boundary beats a plain lowercase run.
        ("ab", "aBc", "abc"),
    ];

    #[test]
    fn indices_are_ordered_positions_of_needle_chars() {
        // Build matchable pairs from random haystacks by sampling a subsequence
        // as the needle; assert the returned indices are the in-order, in-bounds
        // char positions whose characters case-fold to the needle.
        let alphabet: Vec<char> = "abcABC-_/.xyzXYZ019".chars().collect();
        let alen = alphabet.len() as u64;
        let mut rng = lcg(0x5EED_1234_ABCD_0001);
        for _ in 0..1000 {
            // Bounds are tiny, so the modulo result always fits `usize`.
            let hlen = usize::try_from(rng.next().unwrap() % 20).unwrap_or(0) + 1;
            let haystack: String = (0..hlen)
                .map(|_| alphabet[usize::try_from(rng.next().unwrap() % alen).unwrap_or(0)])
                .collect();
            let h_chars: Vec<char> = haystack.chars().collect();
            // Sample an in-order subsequence as the needle (~1 in 3 chars).
            let mut needle = String::new();
            for &c in &h_chars {
                if rng.next().unwrap().is_multiple_of(3) {
                    needle.push(c);
                }
            }
            let Some(m) = fuzzy_match(&needle, &haystack) else {
                // A sampled subsequence must always match.
                assert!(
                    needle.is_empty(),
                    "sampled subsequence {needle:?} did not match {haystack:?}"
                );
                continue;
            };
            let n_chars: Vec<char> = needle.chars().collect();
            assert_eq!(m.indices.len(), n_chars.len());
            let mut prev: Option<u32> = None;
            for (k, &idx) in m.indices.iter().enumerate() {
                assert!((idx as usize) < h_chars.len(), "index out of bounds");
                if let Some(p) = prev {
                    assert!(idx > p, "indices must be strictly increasing");
                }
                prev = Some(idx);
                assert!(
                    char_matches(n_chars[k], h_chars[idx as usize]),
                    "index {idx} char {:?} does not match needle char {:?}",
                    h_chars[idx as usize],
                    n_chars[k]
                );
            }
        }
    }

    #[test]
    fn no_match_returns_none() {
        assert!(fuzzy_match("zzz", "abc").is_none());
        assert!(fuzzy_match("cba", "abc").is_none(), "order matters");
        assert!(fuzzy_match("abcd", "abc").is_none(), "needle longer");
        // Empty needle is a browse-mode match.
        let empty = fuzzy_match("", "abc").unwrap();
        assert_eq!(empty.score, 0);
        assert!(empty.indices.is_empty());
    }

    #[test]
    fn golden_scoring_prefers_documented_fzf_cases() {
        for &(query, better, worse) in GOLDEN_PAIRS {
            let sb = fuzzy_match(query, better)
                .unwrap_or_else(|| panic!("{query:?} should match {better:?}"))
                .score;
            let sw = fuzzy_match(query, worse)
                .unwrap_or_else(|| panic!("{query:?} should match {worse:?}"))
                .score;
            assert!(
                sb > sw,
                "{query:?}: expected {better:?} ({sb}) to outscore {worse:?} ({sw})"
            );
        }
    }

    #[test]
    fn smartcase_behavior() {
        // Lowercase needle: case-insensitive.
        assert!(fuzzy_match("git", "GitHub").is_some());
        // Uppercase needle char is case-sensitive: 'G' needs an uppercase 'G'.
        assert!(fuzzy_match("Git", "digit").is_none());
        assert!(fuzzy_match("Git", "GitHub").is_some());
    }

    #[test]
    fn terms_and_semantics() {
        // Both terms present (in either order across the haystack).
        assert!(fuzzy_match_terms("git jason", "GitHub jason").is_some());
        // A missing term fails the whole match.
        assert!(fuzzy_match_terms("git missing", "GitHub jason").is_none());
        // Indices are merged, sorted, deduped.
        let m = fuzzy_match_terms("ab bc", "abc").unwrap();
        assert_eq!(m.indices, vec![0, 1, 2], "merged, sorted, deduped");
        // Empty query is browse mode.
        let empty = fuzzy_match_terms("   ", "abc").unwrap();
        assert_eq!(empty.score, 0);
        assert!(empty.indices.is_empty());
    }

    #[test]
    fn unicode_char_indices() {
        // Discriminating char-vs-byte test: a multibyte char must precede the
        // matched position so the char index differs from the byte offset. In
        // "naïve" the 2-byte 'ï' sits before 'v', so 'v' is char-index 3 but
        // byte-index 4 — this assertion FAILS under byte indexing.
        let m = fuzzy_match("v", "naïve").expect("v matches naïve");
        assert_eq!(
            m.indices,
            vec![3],
            "index must be a CHAR position, not a byte offset"
        );
        // Every matched char of a multibyte needle carries its char position.
        let m2 = fuzzy_match("nve", "naïve").expect("nve matches naïve");
        assert_eq!(m2.indices, vec![0, 3, 4]);
        // 'é' as the trailing char of "café" (regression: no panic on multibyte).
        assert_eq!(fuzzy_match("é", "café").unwrap().indices, vec![3]);
    }

    #[test]
    fn scoring_is_deterministic() {
        let first = fuzzy_match("gh", "GitHub");
        let second = fuzzy_match("gh", "GitHub");
        assert_eq!(first, second);
    }

    #[test]
    fn optimized_dp_matches_reference_scores_indices_and_ties() {
        let haystacks = [
            "",
            "a",
            "aa",
            "ababa",
            "a-b_c/d.e:f",
            "GitHub",
            "digit",
            "naïve café",
            "AAaaAA",
            "xaybz",
        ];
        let needles = [
            "", "a", "A", "aa", "ab", "aba", "git", "Git", "nve", "é", "zz",
        ];
        for needle in needles {
            for haystack in haystacks {
                assert_eq!(
                    fuzzy_match(needle, haystack),
                    fuzzy_match_reference(needle, haystack),
                    "optimized/reference drift for {needle:?} in {haystack:?}"
                );
            }
        }
    }
}
