// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/encoding/slivers.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Encode and verification paths. `verify`, `check_hash`,
//     `has_correct_length`, `expected_length`, `recovery_symbols`,
//     `get_merkle_root`, `len` and `is_empty` are vendored. The sliver-recovery
//     methods (`recovery_symbol_for_sliver`, `decoding_symbol_for_sliver`, the
//     `recover_sliver_*` family, `check_index`) remain omitted, as do
//     `SliverPair::new_empty`, `recovery_symbol_pair_for_sliver` and
//     `SliverPair::pair_leaf_input`.
//   * NOTE: `recovery_symbols` is not sliver recovery, despite the name. It is
//     the full 1D re-encode out to `n_shards` width whose Merkle root
//     `get_merkle_root` takes, and it is the dominant cost of per-sliver
//     verification — one RS encode plus one Merkle build over `n_shards`
//     leaves, per sliver.
//   * Upstream declares `get_merkle_root` in a separate `impl` block; here it
//     is folded into the single `impl<T: EncodingAxis> SliverData<T>` block.
//   * `SliverData::new` omitted — unused by the encode path.
//   * `Display for SliverData` omitted. Of `SliverPair`'s inherent methods only
//     `index` is retained — it is required by `mapping::rotate_pairs`;
//     `encode_with_metadata` constructs `SliverPair` by struct literal.
//   * Upstream is `#![no_std]` and imports from `alloc`; this crate is std,
//     so those imports are dropped.
//   * Upstream `#[cfg(test)]` code omitted.

//! Sliver types for RedStuff encoding, vendored from walrus-core.

use core::marker::PhantomData;
use core::num::{NonZeroU16, NonZeroU32};

use fastcrypto::hash::{Blake2b256, HashFunction};
use serde::{Deserialize, Serialize};

use super::{
    EncodingAxis,
    EncodingConfig,
    EncodingConfigEnum,
    EncodingFactory as _,
    Primary,
    RecoverySymbolError,
    Secondary,
    SliverVerificationError,
    Symbols,
};
use crate::walrus::vendored::{
    core::{SliverIndex, SliverPairIndex, ensure},
    merkle::{DIGEST_LEN, MerkleTree, Node},
    metadata::{BlobMetadata, BlobMetadataApi as _},
};

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

    /// Checks that the provided sliver is authenticated by the metadata.
    ///
    /// The checks include verifying that the sliver has the correct length and symbol size, and
    /// that the hash in the metadata matches the Merkle root over the sliver's symbols.
    pub fn verify(
        &self,
        encoding_config: &EncodingConfig,
        metadata: &BlobMetadata,
    ) -> Result<(), SliverVerificationError> {
        let encoding_config_for_type = encoding_config.get_for_type(metadata.encoding_type());
        ensure!(
            self.index.as_usize() < metadata.hashes().len(),
            SliverVerificationError::IndexTooLarge
        );
        ensure!(
            self.has_correct_length(&encoding_config_for_type, metadata.unencoded_length()),
            SliverVerificationError::SliverSizeMismatch
        );
        ensure!(
            Ok(self.symbols.symbol_size()) == metadata.symbol_size(encoding_config),
            SliverVerificationError::SymbolSizeMismatch
        );
        self.check_hash(&encoding_config_for_type, metadata)
    }

    /// Checks that the hash of the sliver matches the hash in the metadata.
    ///
    /// This assumes that all relevant size checks have already been performed.
    pub(crate) fn check_hash(
        &self,
        encoding_config: &EncodingConfigEnum,
        metadata: &BlobMetadata,
    ) -> Result<(), SliverVerificationError> {
        let pair_metadata = metadata
            .hashes()
            .get(
                self.index
                    .to_pair_index::<T>(encoding_config.n_shards())
                    .as_usize(),
            )
            .expect("hash must exist if all size checks have been performed");
        ensure!(
            self.get_merkle_root::<Blake2b256>(encoding_config)
                .expect("encoding must work if all size checks have been performed")
                == *pair_metadata.hash::<T>(),
            SliverVerificationError::MerkleRootMismatch
        );
        Ok(())
    }

    /// Returns true iff the sliver has the length expected based on the encoding configuration and
    /// blob size.
    fn has_correct_length(&self, config: &EncodingConfigEnum, blob_size: u64) -> bool {
        self.expected_length(config, blob_size).is_some_and(|l| {
            self.len() == usize::try_from(l).expect("we assume at least a 32-bit architecture")
        })
    }

    fn expected_length(&self, config: &EncodingConfigEnum, blob_size: u64) -> Option<u32> {
        config
            .sliver_size_for_blob::<T>(blob_size)
            .map(NonZeroU32::get)
            .ok()
    }

    /// Creates the first `n_shards` recovery symbols from the sliver.
    ///
    /// [`Primary`] slivers are encoded with the [`Secondary`] encoding, and vice versa, to obtain
    /// the fully-expanded set of recovery symbols.
    ///
    /// # Errors
    ///
    /// Returns a [`RecoverySymbolError::EncodeError`] if the `symbols` cannot be encoded.
    pub fn recovery_symbols(
        &self,
        config: &EncodingConfigEnum,
    ) -> Result<Symbols, RecoverySymbolError> {
        let symbols = config.encode_all_symbols::<T::OrthogonalAxis>(self.symbols.data())?;
        assert!(!symbols.is_empty(), "must be at least 1 symbol");
        assert!(!symbols[0].is_empty(), "symbols must have data");

        Ok(symbols)
    }

    /// Computes the Merkle root [`Node`][`crate::merkle::Node`] of the
    /// [`MerkleTree`][`crate::merkle::MerkleTree`] over the symbols of the expanded [`SliverData`].
    ///
    /// # Errors
    ///
    /// Returns an [`RecoverySymbolError::EncodeError`] if the `symbols` cannot be encoded.
    pub fn get_merkle_root<U: HashFunction<DIGEST_LEN>>(
        &self,
        config: &EncodingConfigEnum,
    ) -> Result<Node, RecoverySymbolError> {
        Ok(MerkleTree::<U>::build(self.recovery_symbols(config)?.to_symbols()).root())
    }

    /// Returns the sliver size in bytes.
    pub fn len(&self) -> usize {
        self.symbols.data().len()
    }

    /// Returns true iff the sliver length is 0.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
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
