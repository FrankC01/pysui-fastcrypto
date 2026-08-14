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
pub mod vendored;
