// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/encoding/blob_encoding.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Encode and decode paths. `BlobDecoder` is vendored.
//     `ExpandedMessageMatrix`, the deprecated `encode_with_metadata_legacy`,
//     `compute_metadata` and the consistency-check helpers remain omitted —
//     this crate verifies a decode by re-encoding the decoded blob through
//     `encode_with_metadata` and comparing blob IDs, which is equivalent in
//     strength to upstream's `Strict` consistency check.
//   * All `tracing` usage is removed, including the `span: Span` field on
//     `BlobEncoderData` and its initializer in `BlobEncoder::new`. The
//     `blob_size` and `blob_prefix` locals fed only that span and are removed
//     with it. This is the only vendored struct whose field list differs from
//     upstream.
//   * Upstream is `#![no_std]` and imports from `alloc`; this crate is std,
//     so those imports are dropped.
//   * Upstream `#[cfg(test)]` code omitted.

//! 2D Reed-Solomon blob encoding, vendored from walrus-core.

use core::{cmp, marker::PhantomData, num::NonZeroU16, ops::Range, slice::Chunks};
use std::collections::BTreeSet;

use fastcrypto::hash::Blake2b256;

use super::{
    DataTooLargeError,
    DecodeError,
    Decoder,
    DecodingSymbol,
    EncodingAxis,
    EncodingConfigEnum,
    EncodingFactory as _,
    Primary,
    ReedSolomonEncoder,
    Secondary,
    SliverData,
    SliverPair,
    Symbols,
    utils,
};
use crate::walrus::vendored::{
    core::{SliverIndex, ensure},
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
    ) -> impl Iterator<Item = SliverData<E>> {
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

/// Struct to reconstruct a blob from either [`Primary`] (default) or [`Secondary`]
/// [`Sliver`s][SliverData].
#[derive(Debug)]
pub struct BlobDecoder<D: Decoder, E: EncodingAxis = Primary> {
    _decoding_axis: PhantomData<E>,
    decoder: D,
    blob_size: usize,
    symbol_size: NonZeroU16,
    sliver_count: usize,
    sliver_length: usize,
    /// The number of columns of the blob's message matrix (i.e., the number of secondary slivers).
    n_columns: usize,
    /// The workspace used to store the sliver data and iteratively overwrite it with the decoded
    /// blob. While a flat byte array, this is interpreted as a matrix of symbols. The layout is the
    /// same as the blob's message matrix; that is, primary slivers are written as "rows" while
    /// secondary slivers are written as "columns".
    workspace: Symbols,
    /// The indices of the slivers that have been provided and added to the workspace.
    sliver_indices: Vec<SliverIndex>,
}

impl<D: Decoder, E: EncodingAxis> BlobDecoder<D, E> {
    /// Creates a new `BlobDecoder` to decode a blob of size `blob_size` using the provided
    /// configuration.
    ///
    /// The generic parameter specifies from which type of slivers the decoding will be performed.
    ///
    /// This function creates the necessary decoders for the decoding; actual decoding can be
    /// performed with the [`decode()`][Self::decode] method.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError::DataTooLarge`] if the `blob_size` is too large to be decoded.
    /// Returns a [`DecodeError::IncompatibleParameters`] if the parameters are incompatible with
    /// the decoder.
    pub fn new(config: &D::Config, blob_size: u64) -> Result<Self, DecodeError> {
        let symbol_size = config.symbol_size_for_blob(blob_size)?;
        let blob_size = blob_size.try_into().map_err(|_| DataTooLargeError)?;
        let n_source_symbols = config.n_source_symbols::<E>();

        let decoder = D::new(n_source_symbols, config.n_shards(), symbol_size)?;

        let sliver_length = config.n_source_symbols::<E::OrthogonalAxis>().get().into();
        let sliver_count = usize::from(n_source_symbols.get());
        let n_symbols_in_workspace = sliver_length * sliver_count;

        let (n_columns, workspace) = if E::IS_PRIMARY {
            (
                sliver_length,
                Symbols::with_capacity(n_symbols_in_workspace, symbol_size),
            )
        } else {
            (
                sliver_count,
                Symbols::zeros(n_symbols_in_workspace, symbol_size),
            )
        };

        Ok(Self {
            _decoding_axis: PhantomData,
            decoder,
            blob_size,
            symbol_size,
            sliver_count,
            sliver_length,
            n_columns,
            workspace,
            sliver_indices: Vec::with_capacity(n_source_symbols.get().into()),
        })
    }

    /// Attempts to decode the source blob from the provided slivers.
    ///
    /// Returns the source blob as a byte vector if decoding succeeds.
    ///
    /// Slivers of incorrect length are dropped.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError::DecodingUnsuccessful`] if decoding was unsuccessful.
    ///
    /// # Panics
    ///
    /// This function can panic if there is insufficient virtual memory for the decoded blob in
    /// addition to the slivers, notably on 32-bit architectures.
    pub fn decode<S>(mut self, slivers: S) -> Result<Vec<u8>, DecodeError>
    where
        S: IntoIterator<Item = SliverData<E>>,
        E: EncodingAxis,
    {
        self.check_and_write_slivers_to_workspace(slivers)?;
        self.perform_decoding()?;

        let mut blob = self.workspace.into_vec();
        blob.truncate(self.blob_size);
        Ok(blob)
    }

    fn check_and_write_slivers_to_workspace(
        &mut self,
        slivers: impl IntoIterator<Item = SliverData<E>>,
    ) -> Result<(), DecodeError> {
        let mut sliver_indices_set = BTreeSet::new();
        let mut slivers_count = 0;
        for sliver in slivers {
            if slivers_count == self.sliver_count {
                break;
            }

            if sliver_indices_set.contains(&sliver.index) {
                continue;
            }

            let expected_len = self.sliver_length;
            let expected_symbol_size = self.symbol_size;
            if sliver.symbols.len() != expected_len
                || sliver.symbols.symbol_size() != expected_symbol_size
            {
                // Drop slivers of incorrect length or incorrect symbol size.
                continue;
            }

            if E::IS_PRIMARY {
                self.write_primary_sliver_to_workspace(sliver.symbols);
            } else {
                self.write_secondary_sliver_to_workspace(sliver.symbols, slivers_count);
            }
            self.sliver_indices.push(sliver.index);
            sliver_indices_set.insert(sliver.index);
            slivers_count += 1;
        }

        ensure!(
            slivers_count == self.sliver_count,
            DecodeError::DecodingUnsuccessful
        );
        Ok(())
    }

    /// Writes the primary sliver as a new row in the workspace.
    fn write_primary_sliver_to_workspace(&mut self, sliver: Symbols) {
        self.workspace
            .extend(sliver.data())
            .expect("we checked above that the symbol size is correct");
    }

    /// Writes the secondary sliver as a column in the workspace.
    fn write_secondary_sliver_to_workspace(&mut self, sliver: Symbols, column: usize) {
        sliver.to_symbols().enumerate().for_each(|(row, symbol)| {
            self.workspace[row * self.n_columns + column].copy_from_slice(symbol);
        });
    }

    fn perform_decoding(&mut self) -> Result<(), DecodeError> {
        for decoder_index in 0..self.sliver_length {
            let symbols = self.sliver_indices.iter().enumerate().map(
                |(sliver_index_in_workspace, sliver_index)| {
                    let index = if E::IS_PRIMARY {
                        sliver_index_in_workspace * self.n_columns + decoder_index
                    } else {
                        decoder_index * self.n_columns + sliver_index_in_workspace
                    };
                    DecodingSymbol::<E>::new(sliver_index.0, self.workspace[index].to_vec())
                },
            );
            let decoded_data = self.decoder.decode(symbols)?;
            // Overwrite the decoding symbols in the workspace with the decoded data.
            if E::IS_PRIMARY {
                for (row_index, symbol) in decoded_data.chunks(self.symbol_usize()).enumerate() {
                    self.workspace[self.n_columns * row_index + decoder_index]
                        .copy_from_slice(symbol);
                }
            } else {
                self.workspace
                    [self.n_columns * decoder_index..self.n_columns * (decoder_index + 1)]
                    .copy_from_slice(&decoded_data);
            }
        }
        Ok(())
    }

    fn symbol_usize(&self) -> usize {
        self.symbol_size.get().into()
    }
}
