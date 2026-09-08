//    Copyright Frank V. Castellucci
//    SPDX-License-Identifier: Apache-2.0

//! Walrus blob encoding and BLS aggregate-signature support.
//!
//! This module provides the primitives required to perform a native Walrus
//! blob upload: RedStuff erasure encoding, blob ID and Merkle root derivation,
//! storage-confirmation message construction, and BLS12-381 signature
//! verification and aggregation.
//!
//! Code under [`vendored`] is derived from walrus-core; see the `NOTICE` file.

pub mod bls;
pub mod ffi;

// `#[rustfmt::skip]` on this declaration stops rustfmt from descending into
// `vendored/`. Naming files on a `cargo fmt` / `rustfmt` command line does NOT
// scope the run -- rustfmt follows `mod` declarations from every file it is
// given, and `src/lib.rs` reaches this whole subtree. Without this attribute a
// plain `cargo fmt` silently repacks the vendored import blocks and destroys
// the file-for-file diffability against upstream that the vendor-drift check
// depends on. rustfmt's `ignore` config option would be the natural guard but
// is nightly-only; this attribute works on stable.
#[rustfmt::skip]
pub mod vendored;

#[cfg(test)]
mod correctness;
