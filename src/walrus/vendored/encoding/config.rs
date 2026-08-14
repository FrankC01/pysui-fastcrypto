// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/encoding/config.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Encode path only. `EncodingFactory` is vendored as a SUBSET: upstream
//     declares 32 methods, of which 25 are decode, quilt or size-calculation
//     methods referencing types this crate deliberately does not vendor
//     (`DecodingSymbol`, `BlobDecoder`, `ConsistencyCheckType`,
//     `RequiredCount`, `DecodeError`). Only the 7 encode-path methods are
//     vendored (7 originally, plus `encode_with_metadata` once
//     `blob_encoding.rs` and `metadata.rs` landed). The `#[enum_dispatch]`
//     structure and the single-variant
//     `EncodingConfigEnum` wrapper are retained for future-proofing against
//     upstream adding further encoding types.
//   * `tracing` calls and `#[tracing::instrument]` attributes are removed;
//     `tracing` is not a dependency of this crate and these are pure
//     observability with no functional effect.
//   * `get_blob_encoder`, `get_blob_encoder_owned` and
//     `EncodingFactory::encode_with_metadata` were deferred during the initial
//     port because they depend on `blob_encoding.rs` and `metadata.rs`. Both
//     have since been vendored, and all three items are now present.
//   * Upstream is `#![no_std]` and imports from `alloc`; this crate is std,
//     so those imports are dropped.
//   * Upstream `#[cfg(test)]` code omitted.

//! Reed-Solomon encoding configuration, vendored from walrus-core.

use std::num::{NonZeroU16, NonZeroU32};

use enum_dispatch::enum_dispatch;

use super::{
    BlobEncoder,
    DataTooLargeError,
    EncodeError,
    EncodingAxis,
    OwnedOrBorrowedBlob,
    ReedSolomonEncoder,
    SliverPair,
    utils,
};
use crate::walrus::vendored::{
    bft,
    core::EncodingType,
    metadata::VerifiedBlobMetadataWithId,
};

/// The maximum number of source symbols that can be encoded with our encoding (currently
/// Reed-Solomon). This is dictated by [`reed_solomon_simd::engine::GF_ORDER`].
pub const MAX_SOURCE_SYMBOLS: u16 = u16::MAX;

/// Trait for encoding functionality, including configuration and encoding.
#[enum_dispatch]
pub trait EncodingFactory {
    /// The encoding type associated with this factory.
    fn encoding_type(&self) -> EncodingType;

    /// Returns the number of primary source symbols as a `NonZeroU16`.
    fn n_primary_source_symbols(&self) -> NonZeroU16;

    /// Returns the number of secondary source symbols as a `NonZeroU16`.
    fn n_secondary_source_symbols(&self) -> NonZeroU16;

    /// Returns the number of shards as a `NonZeroU16`.
    fn n_shards(&self) -> NonZeroU16;

    /// Returns the number of source symbols configured for this type.
    #[inline]
    fn n_source_symbols<E: EncodingAxis>(&self) -> NonZeroU16 {
        if E::IS_PRIMARY {
            self.n_primary_source_symbols()
        } else {
            self.n_secondary_source_symbols()
        }
    }

    /// Returns the number of shards as a `usize`.
    #[inline]
    fn n_shards_as_usize(&self) -> usize {
        self.n_shards().get().into()
    }

    /// The number of symbols a blob is split into.
    #[inline]
    fn source_symbols_per_blob(&self) -> NonZeroU32 {
        utils::source_symbols_per_blob(
            self.n_primary_source_symbols(),
            self.n_secondary_source_symbols(),
        )
    }

    /// Encodes the blob with which `self` was created to a vector of [`SliverPair`s][SliverPair],
    /// and provides the relative [`VerifiedBlobMetadataWithId`].
    ///
    /// This function operates on the fully expanded message matrix for the blob. This matrix is
    /// used to compute the Merkle trees for the metadata, and to extract the sliver pairs. The
    /// returned blob metadata is considered to be verified as it is directly built from the data.
    ///
    /// # Panics
    ///
    /// This function can panic if there is insufficient virtual memory for the encoded data,
    /// notably on 32-bit architectures. As there is an expansion factor of approximately 4.5, blobs
    /// larger than roughly 800 MiB cannot be encoded on 32-bit architectures.
    fn encode_with_metadata(
        &self,
        blob: Vec<u8>,
    ) -> Result<(Vec<SliverPair>, VerifiedBlobMetadataWithId), DataTooLargeError>;
}

/// Configuration parameters for the encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodingConfig {
    /// The number of shards.
    pub(crate) n_shards: NonZeroU16,
    /// The Reed-Solomon encoding config.
    pub reed_solomon: ReedSolomonEncodingConfig,
}

impl EncodingConfig {
    /// Creates a new encoding config, given the number of shards.
    ///
    /// The number of shards determines the the appropriate number of primary and secondary source
    /// symbols.
    ///
    /// # Panics
    ///
    /// Panics if the number of shards causes the number of primary or secondary source symbols
    /// to be larger than [`MAX_SOURCE_SYMBOLS`].
    pub fn new(n_shards: NonZeroU16) -> Self {
        Self {
            n_shards,
            reed_solomon: ReedSolomonEncodingConfig::new(n_shards),
        }
    }

    /// Returns the encoding config for the given encoding type wrapped as an
    /// [`EncodingConfigEnum`].
    pub fn get_for_type(&self, encoding_type: EncodingType) -> EncodingConfigEnum {
        match encoding_type {
            EncodingType::RS2 => self.reed_solomon.into(),
        }
    }

    /// Returns the number of shards.
    pub fn n_shards(&self) -> NonZeroU16 {
        self.n_shards
    }
}

#[enum_dispatch(EncodingFactory)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// A wrapper around the encoding config for different encoding types.
pub enum EncodingConfigEnum {
    /// Configuration of the Reed-Solomon encoding.
    ReedSolomon(ReedSolomonEncodingConfig),
}

/// Configuration of the Reed-Solomon encoding.
///
/// This consists of the number of source symbols for the two encodings and the total number of
/// shards.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ReedSolomonEncodingConfig {
    /// The number of source symbols for the primary encoding, which is, simultaneously, the number
    /// of symbols per secondary sliver. It must be at most `n_shards - 2f`, where `f` is
    /// the Byzantine parameter.
    pub(crate) source_symbols_primary: NonZeroU16,
    /// The number of source symbols for the secondary encoding, which is, simultaneously, the
    /// number of symbols per primary sliver. It must be at most `n_shards - f`, where `f`
    /// is the Byzantine parameter.
    pub(crate) source_symbols_secondary: NonZeroU16,
    /// The number of shards.
    pub(crate) n_shards: NonZeroU16,
}

impl ReedSolomonEncodingConfig {
    const ENCODING_TYPE: EncodingType = EncodingType::RS2;

    /// Creates a new encoding config, given the number of shards.
    ///
    /// The number of shards determines the the appropriate number of primary and secondary source
    /// symbols.
    ///
    /// # Panics
    ///
    /// Panics if the number of shards causes the number of primary or secondary source symbols
    /// to be larger than [`MAX_SOURCE_SYMBOLS`].
    pub fn new(n_shards: NonZeroU16) -> Self {
        let (primary_source_symbols, secondary_source_symbols) =
            source_symbols_for_n_shards(n_shards);
        Self::new_from_nonzero_parameters(
            primary_source_symbols,
            secondary_source_symbols,
            n_shards,
        )
    }

    /// Creates a new encoding configuration for the provided system parameters.
    ///
    /// In a setup with `n_shards` total shards -- among which `f` are Byzantine, and
    /// `f < n_shards / 3` -- `source_symbols_primary` is the number of source symbols for the
    /// primary encoding (must be equal to or below `n_shards - 2f`), and `source_symbols_secondary`
    /// is the number of source symbols for the secondary encoding (must be equal to or below
    /// `n_shards - f`).
    ///
    /// # Panics
    ///
    /// Panics if the parameters are inconsistent with Byzantine fault tolerance; i.e., if the
    /// number of source symbols of the primary encoding is equal to or greater than `n_shards -
    /// 2f`, or if the number of source symbols of the secondary encoding equal to or greater than
    /// `n_shards - f` of the number of shards.
    ///
    /// Panics if the number of primary or secondary source symbols is larger than
    /// [`MAX_SOURCE_SYMBOLS`].
    pub(crate) fn new_from_nonzero_parameters(
        source_symbols_primary: NonZeroU16,
        source_symbols_secondary: NonZeroU16,
        n_shards: NonZeroU16,
    ) -> Self {
        let f = bft::max_n_faulty(n_shards);
        assert!(
            source_symbols_primary.get() < MAX_SOURCE_SYMBOLS
                && source_symbols_secondary.get() < MAX_SOURCE_SYMBOLS,
            "the number of source symbols can be at most `MAX_SOURCE_SYMBOLS`"
        );
        assert!(
            source_symbols_secondary.get() <= n_shards.get() - f,
            "the secondary encoding can be at most a n-f encoding"
        );
        assert!(
            source_symbols_primary.get() <= n_shards.get() - 2 * f,
            "the primary encoding can be at most an n-2f encoding"
        );

        Self {
            source_symbols_primary,
            source_symbols_secondary,
            n_shards,
        }
    }
}

impl ReedSolomonEncodingConfig {
    pub(crate) fn get_encoder<E: EncodingAxis>(
        &self,
        data_length: usize,
    ) -> Result<ReedSolomonEncoder, EncodeError> {
        let symbol_size = ReedSolomonEncoder::check_parameters_and_compute_symbol_size(
            data_length,
            self.n_source_symbols::<E>(),
        )?;
        ReedSolomonEncoder::new(symbol_size, self.n_source_symbols::<E>(), self.n_shards())
    }

    /// Returns a [`BlobEncoder`] for the given blob.
    pub fn get_blob_encoder<'a>(
        &self,
        blob: &'a [u8],
    ) -> Result<BlobEncoder<'a>, DataTooLargeError> {
        BlobEncoder::new((*self).into(), OwnedOrBorrowedBlob::new(blob))
    }

    /// Returns a [`BlobEncoder`] for the given blob.
    pub fn get_blob_encoder_owned(
        &self,
        blob: Vec<u8>,
    ) -> Result<BlobEncoder<'static>, DataTooLargeError> {
        BlobEncoder::new((*self).into(), OwnedOrBorrowedBlob::new_owned(blob))
    }
}

impl EncodingFactory for ReedSolomonEncodingConfig {
    #[inline]
    fn n_primary_source_symbols(&self) -> NonZeroU16 {
        self.source_symbols_primary
    }

    #[inline]
    fn n_secondary_source_symbols(&self) -> NonZeroU16 {
        self.source_symbols_secondary
    }

    #[inline]
    fn n_shards(&self) -> NonZeroU16 {
        self.n_shards
    }

    #[inline]
    fn encoding_type(&self) -> EncodingType {
        ReedSolomonEncodingConfig::ENCODING_TYPE
    }

    fn encode_with_metadata(
        &self,
        blob: Vec<u8>,
    ) -> Result<(Vec<SliverPair>, VerifiedBlobMetadataWithId), DataTooLargeError> {
        Ok(self.get_blob_encoder_owned(blob)?.encode_with_metadata())
    }
}

/// Computes the number of primary encoding and secondary encoding source symbols starting from the
/// number of shards.
///
/// The computation is as follows:
/// - `source_symbols_primary = n_shards - 2f` = # of symbols in secondary sliver
/// - `source_symbols_secondary = n_shards - f` = # of symbols in primary sliver
#[inline]
pub fn source_symbols_for_n_shards(n_shards: NonZeroU16) -> (NonZeroU16, NonZeroU16) {
    let min_n_correct = bft::min_n_correct(n_shards);
    (
        (min_n_correct.get() - bft::max_n_faulty(n_shards))
            .try_into()
            .expect("implied by BFT computations"),
        min_n_correct,
    )
}
