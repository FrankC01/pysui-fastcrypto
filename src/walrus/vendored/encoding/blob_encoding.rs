// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/encoding/blob_encoding.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Encode path only. `BlobDecoder`, `ExpandedMessageMatrix`, the deprecated
//     `encode_with_metadata_legacy`, `compute_metadata` and the consistency-check
//     helpers are omitted.
//   * All `tracing` usage is removed, including the `span: Span` field on
//     `BlobEncoderData` and its initializer in `BlobEncoder::new`. The
//     `blob_size` and `blob_prefix` locals fed only that span and are removed
//     with it. This is the only vendored struct whose field list differs from
//     upstream.
//   * Upstream is `#![no_std]` and imports from `alloc`; this crate is std,
//     so those imports are dropped.
//   * `empty_slivers_range` gains an explicit `+ '_` on its return type.
//     walrus-core is edition 2024, where `impl Trait` return types capture all
//     in-scope lifetimes automatically (RFC 3498); this crate is edition 2021,
//     where they do not, so the verbatim signature fails with E0700. `+ '_` is
//     precisely what edition 2024 infers.
//   * Upstream `#[cfg(test)]` code omitted.

//! 2D Reed-Solomon blob encoding, vendored from walrus-core.

use core::{cmp, num::NonZeroU16, ops::Range, slice::Chunks};

use fastcrypto::hash::Blake2b256;

use super::{
    DataTooLargeError,
    EncodingAxis,
    EncodingConfigEnum,
    EncodingFactory as _,
    Primary,
    ReedSolomonEncoder,
    Secondary,
    SliverData,
    SliverPair,
    utils,
};
use crate::walrus::vendored::{
    core::SliverIndex,
    merkle::{MerkleTree, Node, leaf_hash},
    metadata::{SliverPairMetadata, VerifiedBlobMetadataWithId},
};

/// A wrapper around a blob that can be either owned (i.e., `Vec<u8>`) or borrowed (`&[u8]`).
#[derive(Debug)]
pub enum OwnedOrBorrowedBlob<'a> {
    /// An owned blob.
    Owned(Vec<u8>),
    /// A borrowed blob.
    Borrowed(&'a [u8]),
}

impl<'a> OwnedOrBorrowedBlob<'a> {
    /// Creates a new `OwnedOrBorrowedBlob` from a borrowed blob.
    pub fn new(blob: &'a [u8]) -> Self {
        Self::Borrowed(blob)
    }

    /// Returns the length of the blob.
    pub fn len(&self) -> usize {
        match self {
            Self::Borrowed(blob) => blob.len(),
            Self::Owned(blob) => blob.len(),
        }
    }
}

impl OwnedOrBorrowedBlob<'static> {
    /// Creates a new `OwnedOrBorrowedBlob` from an owned blob.
    pub fn new_owned(blob: Vec<u8>) -> Self {
        Self::Owned(blob)
    }
}

impl<'a> AsRef<[u8]> for OwnedOrBorrowedBlob<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(blob) => blob,
            Self::Owned(blob) => blob,
        }
    }
}

/// Inner state of the blob encoder that doesn't contain the actual blob data.
#[derive(Debug, Clone)]
struct BlobEncoderData {
    /// The size of the encoded and decoded symbols.
    symbol_size: NonZeroU16,
    /// The number of rows of the message matrix.
    ///
    /// Stored as a `usize` for convenience, but guaranteed to be non-zero.
    n_rows: NonZeroU16,
    /// The number of columns of the message matrix.
    ///
    /// Stored as a `usize` for convenience, but guaranteed to be non-zero.
    n_columns: NonZeroU16,
    /// Reference to the encoding configuration of this encoder.
    config: EncodingConfigEnum,
}

impl BlobEncoderData {
    fn get_encoder<E: EncodingAxis>(&self) -> ReedSolomonEncoder {
        let EncodingConfigEnum::ReedSolomon(encoding_config) = self.config;
        encoding_config
            .get_encoder::<E>(self.sliver_length::<E::OrthogonalAxis>())
            .expect("this length is compatible with the encoder")
    }

    /// Returns the size of the symbol in bytes.
    pub fn symbol_usize(&self) -> usize {
        self.symbol_size.get().into()
    }

    fn sliver_length<E: EncodingAxis>(&self) -> usize {
        usize::from(self.config.n_source_symbols::<E::OrthogonalAxis>().get()) * self.symbol_usize()
    }

    fn empty_sliver<E: EncodingAxis>(&self, index: SliverIndex) -> SliverData<E> {
        SliverData::<E>::new_empty(
            self.config.n_source_symbols::<E::OrthogonalAxis>().get(),
            self.symbol_size,
            index,
        )
    }

    fn empty_slivers<E: EncodingAxis>(&self) -> Vec<SliverData<E>> {
        self.empty_slivers_range::<E>(0..self.config.n_shards().get())
            .collect()
    }

    fn empty_slivers_range<E: EncodingAxis>(
        &self,
        range: Range<u16>,
    ) -> impl Iterator<Item = SliverData<E>> + '_ {
        range.map(|i| self.empty_sliver::<E>(SliverIndex(i)))
    }

    /// Computes the blob metadata from the provided leaf hashes of all symbols.
    ///
    /// The provided slice *must* be of length `n_shards * n_shards`, where `n_shards` is the number
    /// of shards. The slice is interpreted as a matrix in row-major order.
    ///
    /// # Panics
    ///
    /// Panics if the length of the provided slice is not equal to `n_shards * n_shards`.
    pub fn compute_metadata_from_symbol_hashes(
        config: EncodingConfigEnum,
        symbol_hashes: &[Node],
        unencoded_length: u64,
    ) -> VerifiedBlobMetadataWithId {
        let n_shards = config.n_shards_as_usize();
        assert_eq!(symbol_hashes.len(), n_shards * n_shards);

        let mut metadata = Vec::with_capacity(n_shards);
        for sliver_index in 0..n_shards {
            let primary_hash = MerkleTree::<Blake2b256>::build_from_leaf_hashes(
                symbol_hashes[n_shards * sliver_index..n_shards * (sliver_index + 1)]
                    .iter()
                    .cloned(),
            )
            .root();
            let secondary_hash = MerkleTree::<Blake2b256>::build_from_leaf_hashes(
                (0..n_shards).map(|symbol_index| {
                    symbol_hashes[n_shards * symbol_index + n_shards - 1 - sliver_index].clone()
                }),
            )
            .root();
            metadata.push(SliverPairMetadata {
                primary_hash,
                secondary_hash,
            })
        }

        VerifiedBlobMetadataWithId::new_verified_from_metadata(
            metadata,
            config.encoding_type(),
            unencoded_length,
        )
    }

    fn n_rows_usize(&self) -> usize {
        self.n_rows.get().into()
    }

    fn n_columns_usize(&self) -> usize {
        self.n_columns.get().into()
    }

    fn n_shards_usize(&self) -> usize {
        self.config.n_shards_as_usize()
    }
}

/// Struct to perform the full blob encoding.
#[derive(Debug)]
pub struct BlobEncoder<'a> {
    /// A reference to the blob.
    // INV: `blob.len() > 0`
    // TODO(WAL-1093): Consider using a `Bytes` object here instead or add it as a variant to the
    // `OwnedOrBorrowedBlob`.
    blob: OwnedOrBorrowedBlob<'a>,
    /// Inner state that doesn't depend on the blob data.
    inner: BlobEncoderData,
}

impl<'a> BlobEncoder<'a> {
    /// Creates a new `BlobEncoder` to encode the provided `blob` with the provided configuration.
    ///
    /// The actual encoding can be performed with the
    /// [`encode_with_metadata()`][Self::encode_with_metadata] method.
    ///
    /// # Errors
    ///
    /// Returns a [`DataTooLargeError`] if the blob is too large to be encoded. This can happen in
    /// two cases:
    ///
    /// 1. If the blob is too large to fit into the message matrix with valid symbols. The maximum
    ///    blob size for a given [`EncodingConfigEnum`] is accessible through the
    ///    [`EncodingConfigEnum::max_blob_size`] method.
    /// 2. On 32-bit architectures, the maximally supported blob size can actually be smaller than
    ///    that due to limitations of the address space.
    pub fn new(
        config: EncodingConfigEnum,
        blob: OwnedOrBorrowedBlob<'a>,
    ) -> Result<Self, DataTooLargeError> {
        let symbol_size = utils::compute_symbol_size_from_usize(
            blob.len(),
            config.source_symbols_per_blob(),
            config.encoding_type().required_alignment(),
        )?;
        let n_rows = config.n_source_symbols::<Primary>();
        let n_columns = config.n_source_symbols::<Secondary>();

        Ok(Self {
            blob,
            inner: BlobEncoderData {
                symbol_size,
                n_rows,
                n_columns,
                config,
            },
        })
    }

    /// Encodes the blob with which `self` was created to a vector of [`SliverPair`s][SliverPair],
    /// and provides the relative [`VerifiedBlobMetadataWithId`].
    ///
    /// The returned blob metadata is considered to be verified as it is directly built from the
    /// data.
    ///
    /// # Panics
    ///
    /// This function can panic if there is insufficient virtual memory for the encoded data,
    /// notably on 32-bit architectures. As there is an expansion factor of approximately 4.5, blobs
    /// larger than roughly 800 MiB cannot be encoded on 32-bit architectures.
    pub fn encode_with_metadata(self) -> (Vec<SliverPair>, VerifiedBlobMetadataWithId) {
        let unencoded_length =
            u64::try_from(self.blob.len()).expect("any valid blob size fits into a `u64`");

        // Only allocate empty systematic primary slivers upfront to limit peak memory usage.
        let mut primary_slivers = Vec::with_capacity(self.inner.n_shards_usize());
        primary_slivers.extend(
            self.inner
                .empty_slivers_range::<Primary>(0..self.inner.n_rows.get()),
        );
        let mut secondary_slivers = self.inner.empty_slivers::<Secondary>();

        // The first `n_rows` primary slivers and the last `n_columns` secondary slivers can be
        // directly copied from the blob.
        for (row, sliver) in self.rows().zip(primary_slivers.iter_mut()) {
            sliver.symbols.data_mut()[..row.len()].copy_from_slice(row);
        }
        for (column, sliver) in self.column_symbols().zip(secondary_slivers.iter_mut()) {
            sliver
                .symbols
                .to_symbols_mut()
                .zip(column)
                .for_each(|(dest, src)| dest[..src.len()].copy_from_slice(src))
        }

        drop(self.blob);

        // Compute the remaining secondary slivers by encoding the rows (i.e., primary slivers)
        // using the secondary encoding.
        let mut secondary_encoder = self.inner.get_encoder::<Secondary>();
        for (r, row) in primary_slivers
            .iter()
            .take(self.inner.n_rows_usize())
            .enumerate()
        {
            let encode_result = secondary_encoder
                .encode(row.symbols.data())
                .expect("size has already been checked");
            for (symbol, sliver) in encode_result.recovery_iter().zip(
                secondary_slivers
                    .iter_mut()
                    .skip(self.inner.n_columns_usize()),
            ) {
                sliver.copy_symbol_to(r, symbol);
            }
        }
        drop(secondary_encoder);

        // Now we can encode all secondary slivers, computing the remaining primary slivers and all
        // symbol hashes.
        let n_shards = self.inner.config.n_shards_as_usize();
        let mut symbol_hashes = vec![Node::Empty; n_shards * n_shards];

        // Create the non-systematic primary slivers.
        primary_slivers.extend(self.inner.empty_slivers_range::<Primary>(
            self.inner.n_rows.get()..self.inner.config.n_shards().get(),
        ));

        let mut primary_encoder = self.inner.get_encoder::<Primary>();
        for (col_index, column) in secondary_slivers.iter().enumerate() {
            let symbols = primary_encoder
                .encode_all_ref(column.symbols.data())
                .expect("size has already been checked");
            for (row_index, symbol) in symbols.to_symbols().enumerate() {
                symbol_hashes[n_shards * row_index + col_index] = leaf_hash::<Blake2b256>(symbol);
            }
            if col_index < self.inner.n_columns_usize() {
                for (symbol, sliver) in symbols
                    .to_symbols()
                    .zip(primary_slivers.iter_mut())
                    .skip(self.inner.n_rows_usize())
                {
                    sliver.copy_symbol_to(col_index, symbol);
                }
            }
        }
        drop(primary_encoder);

        let sliver_pairs = primary_slivers
            .into_iter()
            .zip(secondary_slivers.into_iter().rev())
            .map(|(primary, secondary)| SliverPair { primary, secondary })
            .collect();
        let metadata = BlobEncoderData::compute_metadata_from_symbol_hashes(
            self.inner.config,
            &symbol_hashes,
            unencoded_length,
        );
        (sliver_pairs, metadata)
    }

    /// Returns a reference to the blob data.
    pub fn blob(&self) -> &[u8] {
        self.blob.as_ref()
    }

    // Forwarding methods to inner

    /// Returns the size of the symbol in bytes.
    pub fn symbol_usize(&self) -> usize {
        self.inner.symbol_usize()
    }

    /// Returns a reference to the symbol at the provided indices in the message matrix.
    ///
    /// The length of the returned slice can be lower than `self.symbol_size` if the blob needs to
    /// be padded.
    fn symbol_at(&self, row_index: usize, col_index: usize) -> &[u8] {
        let start_index = cmp::min(
            self.symbol_usize() * (self.inner.n_columns_usize() * row_index + col_index),
            self.blob.len(),
        );
        let end_index = cmp::min(start_index + self.symbol_usize(), self.blob.len());
        self.blob()[start_index..end_index].as_ref()
    }

    fn column_symbols(
        &self,
    ) -> impl ExactSizeIterator<Item = impl ExactSizeIterator<Item = &[u8]>> {
        (0..self.inner.n_columns_usize()).map(move |col_index| {
            (0..self.inner.n_rows_usize())
                .map(move |row_index| self.symbol_at(row_index, col_index))
        })
    }

    fn rows(&self) -> Chunks<'_, u8> {
        self.blob()
            .chunks(self.inner.n_columns_usize() * self.symbol_usize())
    }
}
