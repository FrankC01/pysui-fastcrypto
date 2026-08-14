// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/encoding/slivers.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Encode path only. All verification, recovery and decoding methods are
//     omitted.
//   * `SliverData::new` omitted — unused by the encode path.
//   * `Display for SliverData` omitted. Of `SliverPair`'s inherent methods only
//     `index` is retained — it is required by `mapping::rotate_pairs`;
//     `encode_with_metadata` constructs `SliverPair` by struct literal.
//   * Upstream is `#![no_std]` and imports from `alloc`; this crate is std,
//     so those imports are dropped.
//   * Upstream `#[cfg(test)]` code omitted.

//! Sliver types for RedStuff encoding, vendored from walrus-core.

use core::marker::PhantomData;
use core::num::NonZeroU16;

use serde::{Deserialize, Serialize};

use super::{EncodingAxis, Primary, Secondary, Symbols};
use crate::walrus::vendored::core::{SliverIndex, SliverPairIndex};

/// A primary sliver resulting from an encoding of a blob.
pub type PrimarySliver = SliverData<Primary>;

/// A secondary sliver resulting from an encoding of a blob.
pub type SecondarySliver = SliverData<Secondary>;

/// Encoded data corresponding to a single [`EncodingAxis`] assigned to one shard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliverData<T: EncodingAxis> {
    /// The encoded data.
    pub symbols: Symbols,
    /// Index of this sliver.
    ///
    /// This is needed for the decoding to be able to identify the encoded symbols.
    pub index: SliverIndex,
    _sliver_type: PhantomData<T>,
}

impl<T: EncodingAxis> SliverData<T> {
    /// Creates a new `Sliver` with empty data of specified length.
    ///
    /// The `length` parameter specifies the number of symbols.
    pub fn new_empty(length: u16, symbol_size: NonZeroU16, index: SliverIndex) -> Self {
        Self {
            symbols: Symbols::zeros(length.into(), symbol_size),
            index,
            _sliver_type: PhantomData,
        }
    }

    /// Copies the provided symbol to the location specified by the index.
    ///
    /// # Panics
    ///
    /// Panics if `self.data.len() < index * (symbol.len() + 1)` and if the symbol size does not
    /// match the length specified in the [`Symbols`] struct.
    pub fn copy_symbol_to(&mut self, index: usize, symbol: &[u8]) -> &mut Self {
        assert!(symbol.len() == self.symbols.symbol_usize());
        self.symbols[index].copy_from_slice(symbol);
        self
    }
}

/// Combination of a primary and secondary sliver of one shard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliverPair {
    /// The sliver corresponding to the [`Primary`] encoding.
    pub primary: PrimarySliver,
    /// The sliver corresponding to the [`Secondary`] encoding.
    pub secondary: SecondarySliver,
}

impl SliverPair {
    /// Index of this sliver pair.
    ///
    /// Sliver pair `i` contains the primary sliver `i` and the secondary sliver `n_shards-i-1`.
    pub fn index(&self) -> SliverPairIndex {
        self.primary.index.into()
    }
}
