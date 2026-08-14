# Vendor Upstream State

Boundary commits for `/vendor-drift-check`. Each entry records the last commit
reviewed for that upstream. Diff forward from these — do not scan full history.

## walrus

- **Clone:** `~/mysten_repos/walrus`
- **Last reviewed:** `14641cc0edcc727825d07aa19df2eef8046a3c0d`
- **Reviewed on:** 2026-08-14
- **Ground truth:** `scratch/vendor-drift/ground_truth-14641cc0.txt` (782 items across 17 files)
- **Findings:** Initial boundary — no drift review has run yet. This is the commit
  the vendored code in `src/walrus/vendored/` was ported from; every provenance
  header, the `NOTICE` file, and `scratch/vendor-drift/walrus-port-manifest.md` cite it.

## fastcrypto

- **Clone:** `~/mysten_repos/fastcrypto`
- **Last reviewed:** `47f8f6b747900bbc1662c4d4eecd2f7e7a29e16a` (tag `fastcrypto-v0.1.11`)
- **Reviewed on:** 2026-08-14
- **Findings:** Initial boundary — no drift review has run yet.

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
