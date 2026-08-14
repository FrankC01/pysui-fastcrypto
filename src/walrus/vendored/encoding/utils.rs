// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/encoding/utils.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Only the symbol-size and source-symbol helpers used by the encode path.
//   * Upstream `#[cfg(test)]` code omitted.

//! Symbol-size helpers, vendored from walrus-core.

use core::num::{NonZeroU16, NonZeroU32};

use super::DataTooLargeError;

/// Computes the correct symbol size given the data length and the number of source symbols.
#[inline]
pub fn compute_symbol_size(
    data_length: u64,
    n_symbols: NonZeroU32,
    required_alignment: u16,
) -> Result<NonZeroU16, DataTooLargeError> {
    // Use a 1-byte symbol size for the empty blob.
    let data_length = data_length.max(1);
    let symbol_size = data_length
        .div_ceil(u64::from(n_symbols.get()))
        .next_multiple_of(required_alignment.into());

    Ok(
        NonZeroU16::new(u16::try_from(symbol_size).map_err(|_| DataTooLargeError)?)
            .expect("we start with something positive and always round up"),
    )
}

/// Computes the correct symbol size given the data length and the number of source symbols.
#[inline]
pub fn compute_symbol_size_from_usize(
    data_length: usize,
    n_symbols: NonZeroU32,
    required_alignment: u16,
) -> Result<NonZeroU16, DataTooLargeError> {
    compute_symbol_size(
        data_length.try_into().map_err(|_| DataTooLargeError)?,
        n_symbols,
        required_alignment,
    )
}

/// The number of symbols a blob is split into.
#[inline]
pub fn source_symbols_per_blob(
    source_symbols_primary: NonZeroU16,
    source_symbols_secondary: NonZeroU16,
) -> NonZeroU32 {
    NonZeroU32::from(source_symbols_primary)
        .checked_mul(source_symbols_secondary.into())
        .expect("product of two u16 always fits into a u32")
}
