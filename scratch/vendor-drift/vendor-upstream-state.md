# Vendor Upstream State

Boundary commits for `/vendor-drift-check`. Each entry records the last commit
reviewed for that upstream. Diff forward from these — do not scan full history.

## walrus

- **Clone:** `~/mysten_repos/walrus`
- **Last reviewed:** `cd276427bf89517cf227c701918ef162743279b9` (pin unchanged: `14641cc0edcc727825d07aa19df2eef8046a3c0d`)
- **Reviewed on:** 2026-09-05
- **Ground truth:** `scratch/vendor-drift/ground_truth-14641cc0.txt` (782 items across 17 files) — not regenerated, still valid: all 17 watched files are byte-for-byte identical to the pinned commit (confirmed via `git diff --stat`, empty output).
- **Findings:** No drift. 8 commits landed between the pin and new HEAD
  (`558f40f2ac`, `9c02b425d2`, `8efe66024d`, `a744799a5f`, `450e06de73`,
  `51ebea3fa0`, `8cb55c2511`, `2f8983b169`), all touching only the workspace-root
  `Cargo.toml` (walrus version bumps, Sui-testnet CI pin bumps, an unused-dep
  removal, a dbtool feature dep addition, a `num-bigint` patch bump) — none touch
  `crates/walrus-core/Cargo.toml`, `reed-solomon-simd` (still `3.1.0`), the
  workspace `edition` (still `2024`), or any of the 17 watched source files.
  `classify.py` completeness check: 672 live items, 0 unclassified, 0 swallowed,
  52 phantom ranges (up from the 48 documented in `README.md`'s 2026-08-14
  baseline — the +4 is fully explained by the manifest's own 2026-08-16
  `EncodingType` correction commit adding narrative line-citations, not by any
  upstream change; see `README.md`'s phantom-range note).

## fastcrypto

- **Clone:** `~/mysten_repos/fastcrypto`
- **Last reviewed:** `47f8f6b747900bbc1662c4d4eecd2f7e7a29e16a` (tag `fastcrypto-v0.1.11`) — boundary unchanged, still the latest `fastcrypto-vX.Y.Z` tag; no new crates.io release.
- **Reviewed on:** 2026-09-05
- **Findings:** No drift. Clone HEAD advanced to `0655d5fb624dd60c0f83673af3a9c66d9b6d2539`,
  4 commits past the tag touch `fastcrypto/Cargo.toml` (`0655d5fb6` BulletProofs++,
  `4ca2b919d` remove `unsecure` module, `562bf1e69` Ristretto MSM switcher,
  `46caa7be6` move sphincs to `fastcrypto-pq`) but none touch
  `fastcrypto/src/bls12381/min_pk/mod.rs`, `fastcrypto/src/bls12381/mod.rs`
  (the `define_bls12381!` macro), or `fastcrypto/src/groups/bls12381.rs` — all
  three confirmed zero-diff via `git diff`. `version = "0.1.11"` unchanged (still
  unreleased dev state past the tag). Note: `fastcrypto-v1.0.0`/`fastcrypto-v2.0.0`
  tags exist in the clone but are 2022-era legacy tags predating the
  `fastcrypto/` crate subdirectory (no `fastcrypto/Cargo.toml` at those refs) —
  not real releases of this crate, disregarded.

**The boundary is the TAG, not the clone HEAD.** This crate depends on crates.io
`fastcrypto = "0.1.11"`, so the relevant boundary is the commit the published
0.1.11 release was cut from. The local clone currently sits at
`fastcrypto-v0.1.11-18-ga9f994cd6` — 18 commits past that tag — and none of those
commits are in what this crate compiles. Diffing from clone HEAD would report
changes that cannot affect us, while missing the question that actually matters:
whether a new crates.io release has landed.

Note also that walrus pins fastcrypto by git rev
(`4db0e90c732bbf7420ca20de808b698883148d9c`), which is a different Cargo source
from ours even where byte-identical. See the source-identity caveat in the
drift-check command.
