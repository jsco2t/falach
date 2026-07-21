# EFF Large Wordlist — Provenance and License

**File:** `crates/falach-genpw/src/assets/eff_large_wordlist.txt`
**Source:** https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
**Article:** https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
**Downloaded:** 2026-05-21
**SHA-256:** `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`
**Word count:** 7,776 (= 6⁵, five dice rolls per word)
**Format:** UTF-8 (ASCII-only in practice), LF line endings, no BOM. Each line is
`<5-digit-dice-prefix>\t<word>\n`. First line: `11111\tabacus`. Last line:
`66666\tzoom`.

## License status

The Electronic Frontier Foundation (EFF) published this wordlist in July 2016
specifically for use in password / passphrase generators. The accompanying
article explicitly states EFF's intent that the wordlist be freely reused.
Lists of common-English words are not copyrightable under U.S. law (lists of
facts / non-creative compilations).

The most conservative interpretation consistent with Falach's supply-chain
policy (`kb/supply-chain-policy.md`) is to treat this file as effectively
public-domain or CC0-1.0 equivalent. CC0-1.0 is on Falach's permissive-license
allow-list (`deny.toml`).

This file is **not** part of the Cargo dependency graph; it is an embedded
asset compiled into the binary via `include_str!`. `cargo deny`'s license
review does not apply to it. This document is the project's record of due
diligence — checked into the repository alongside the asset itself.

## Verification

To verify the embedded file matches the canonical EFF release:

    sha256sum crates/falach-genpw/src/assets/eff_large_wordlist.txt

The output must match the SHA-256 listed above. A mismatch indicates either
the EFF has updated the file (extremely unlikely; it has been stable since
the original July 2016 release) or the embedded asset has been altered.
Either case requires PR review and an update to this provenance document.

The crate also contains an automated test
(`crates/falach-genpw/src/wordlist.rs::tests::first_and_last_words_match_canonical_eff_list`)
that fails fast if the embedded asset is swapped for a different wordlist —
e.g., the smaller EFF short list (1,296 words) — without going through this
provenance update path.
