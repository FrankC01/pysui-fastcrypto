// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/encoding/errors.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Encode path only; all decode, recovery, verification and quilt error
//     types are omitted.
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

/// Error returned when the size of input symbols does not match the size of existing symbols.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
#[error("the size of the symbols provided does not match the size of the existing symbols")]
pub struct WrongSymbolSizeError;
