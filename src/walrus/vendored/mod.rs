//    Copyright Frank V. Castellucci
//    SPDX-License-Identifier: Apache-2.0

//! Code vendored from walrus-core, pinned at commit `14641cc0`.
//!
//! Files in this module mirror the upstream module layout so that drift
//! against walrus-core can be diffed file by file. They contain NO PyO3
//! annotations. See `NOTICE` and `scratch/vendor-drift/walrus-port-manifest.md`.

pub mod bft;
pub mod core;
pub mod encoding;
pub mod merkle;
pub mod messages;
pub mod metadata;
pub mod utils;
