// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/encoding/errors.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Encode, decode and verification paths. `DecodeError`,
//     `SliverVerificationError`, `RecoverySymbolError` and their `From` impls
//     are vendored. `RecoverySymbolError` is required not by sliver recovery,
//     which is out of scope, but by `SliverData::recovery_symbols`, which the
//     verification path uses to rebuild a sliver's expanded symbol set before
//     hashing it. Quilt error types and the sliver-recovery error types
//     (`SliverRecoveryError`, `SliverRecoveryOrVerificationError`,
//     `WrongSliverVariantError`, `SymbolVerificationError`) remain omitted.
//   * Upstream is `#![no_std]` and imports `String`/`Vec` from `alloc`;
//     this crate is std, so those imports are dropped (both are in the
//     std prelude).
//   * Upstream `#[cfg(test)]` code omitted.

//! Error types for the encode path, vendored from walrus-core.

use thiserror::Error;

/// Error indicating that the data is too large to be encoded/decoded.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
#[error("the data is too large to be encoded/decoded")]
pub struct DataTooLargeError;

/// Error returned when encoding/decoding is impossible due to the given data size.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum InvalidDataSizeError {
    /// The data is too large to be encoded/decoded.
    #[error("the data is too large")]
    DataTooLarge,
    /// The data to be encoded/decoded is empty.
    #[error("the data is empty")]
    EmptyData,
}

impl From<DataTooLargeError> for InvalidDataSizeError {
    fn from(_value: DataTooLargeError) -> Self {
        Self::DataTooLarge
    }
}

/// Error type returned when encoding fails.
#[derive(Debug, Error, PartialEq, Clone)]
pub enum EncodeError {
    /// The data size is invalid for this encoder.
    #[error(transparent)]
    InvalidDataSize(#[from] InvalidDataSizeError),
    /// The data length is not supported by this encoder.
    #[error("the data length is incorrect (expected: {0})")]
    IncorrectDataLength(usize),
    /// The parameters are incompatible with the encoder.
    #[error("the parameters are incompatible with the encoder: {0}")]
    IncompatibleParameters(String),
}

/// Error type returned when decoding fails.
#[derive(Debug, Error, PartialEq, Clone)]
pub enum DecodeError {
    /// The blob size is too large to be decoded.
    #[error("the blob size is too large to be decoded")]
    DataTooLarge,
    /// The parameters are incompatible with the Reed-Solomon decoder.
    #[error("the parameters are incompatible with the Reed-Solomon decoder: {0}")]
    IncompatibleParameters(reed_solomon_simd::Error),
    /// An error occurred while decoding.
    #[error("an error occurred in the underlying Reed-Solomon decoder: {0}")]
    DecoderError(#[from] reed_solomon_simd::Error),
    /// The decoding was unsuccessful. Most likely not enough symbols/slivers were provided.
    #[error("decoding was unsuccessful; most likely not enough symbols/slivers were provided")]
    DecodingUnsuccessful,
    /// Error returned when the verification of a reconstructed blob fails. Verification failure
    /// occurs when the provided blob ID does not match the blob ID computed from the reconstructed
    /// blob.
    #[error("decoding verification failed: the blob ID does not match the provided metadata")]
    VerificationError,
}

impl From<DataTooLargeError> for DecodeError {
    fn from(_value: DataTooLargeError) -> Self {
        Self::DataTooLarge
    }
}

/// Error type returned when computing recovery symbols fails.
#[derive(Debug, Error, PartialEq, Clone)]
pub enum RecoverySymbolError {
    /// The index of the recovery symbol can be at most `n_shards`.
    #[error("the index of the recovery symbol can be at most `n_shards`")]
    IndexTooLarge,
    /// The underlying basic encoder returned an error.
    #[error(transparent)]
    EncodeError(#[from] EncodeError),
}

impl From<InvalidDataSizeError> for RecoverySymbolError {
    fn from(value: InvalidDataSizeError) -> Self {
        EncodeError::from(value).into()
    }
}

/// Error returned when sliver verification fails.
#[derive(Debug, Error, PartialEq, Clone)]
pub enum SliverVerificationError {
    /// The sliver index is too large for the number of shards in the metadata.
    #[error("the sliver index is too large for the number of shards in the metadata")]
    IndexTooLarge,
    /// The length of the provided sliver does not match the number of source symbols in the
    /// metadata.
    #[error("the length of the provided sliver does not match the metadata")]
    SliverSizeMismatch,
    /// The symbol size of the provided sliver does not match the symbol size that can be computed
    /// from the metadata.
    #[error("the symbol size of the provided sliver does not match the metadata")]
    SymbolSizeMismatch,
    /// The recomputed Merkle root of the provided sliver does not match the root stored in the
    /// metadata.
    #[error("the recomputed Merkle root of the provided sliver does not match the metadata")]
    MerkleRootMismatch,
}

/// Error returned when the size of input symbols does not match the size of existing symbols.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
#[error("the size of the symbols provided does not match the size of the existing symbols")]
pub struct WrongSymbolSizeError;
