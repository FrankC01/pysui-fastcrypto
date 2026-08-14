// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/encoding/basic_encoding.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Encoder only. The `Decoder` trait and `ReedSolomonDecoder` are not
//     vendored, nor are the quilt attribute constants.
//   * `tracing` calls and attributes removed; `tracing` is not a dependency
//     of this crate and these are pure observability.
//   * Upstream writes `crate::ensure!(...)`; here the vendored macro is
//     imported from `vendored::core` and invoked as `ensure!(...)`.
//   * Upstream is `#![no_std]` and imports from `alloc`; this crate is std,
//     so those imports are dropped.
//   * Upstream `#[cfg(test)]` code omitted.

//! Reed-Solomon encoder, vendored from walrus-core.

use std::fmt;
use std::num::NonZeroU16;

use reed_solomon_simd::{self, EncoderResult};

use super::{EncodeError, InvalidDataSizeError, Symbols, utils};
use crate::walrus::vendored::core::{ensure, EncodingType};

/// Wrapper to perform a single encoding with Reed-Solomon for the provided parameters.
// INV: n_source_symbols <= n_shards.
pub struct ReedSolomonEncoder {
    encoder: reed_solomon_simd::ReedSolomonEncoder,
    n_source_symbols: NonZeroU16,
    n_shards: NonZeroU16,
    symbol_size: NonZeroU16,
    // Keep a buffer to avoid allocating a new `Symbols` object during every encoding.
    encoded_symbols: Option<Symbols>,
}

impl fmt::Debug for ReedSolomonEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReedSolomonEncoder")
            .field("n_source_symbols", &self.n_source_symbols)
            .field("n_shards", &self.n_shards)
            .field("symbol_size", &self.symbol_size)
            .finish()
    }
}

impl ReedSolomonEncoder {
    const ASSOCIATED_ENCODING_TYPE: EncodingType = EncodingType::RS2;

    /// Creates a new `Encoder` for the provided parameters.
    ///
    /// `n_shards` is the total number of shards for which symbols should be generated. The number
    /// of shards must be at least `n_source_symbols`.
    ///
    /// # Errors
    ///
    /// Returns an [`EncodeError`] if the `symbol_size` is not a multiple of the required alignment,
    /// `n_shards` is less than `n_source_symbols`, or the parameters are otherwise incompatible
    /// with a Reed-Solomon encoder.
    pub fn new(
        symbol_size: NonZeroU16,
        n_source_symbols: NonZeroU16,
        n_shards: NonZeroU16,
    ) -> Result<Self, EncodeError> {
        ensure!(
            n_shards >= n_source_symbols,
            EncodeError::IncompatibleParameters(
                "n_shards must be at least n_source_symbols".into()
            ),
        );
        ensure!(
            symbol_size
                .get()
                .is_multiple_of(Self::ASSOCIATED_ENCODING_TYPE.required_alignment()),
            EncodeError::IncompatibleParameters(
                "symbol_size must be a multiple of the required alignment".into(),
            ),
        );

        let encoder = reed_solomon_simd::ReedSolomonEncoder::new(
            Self::reed_solomon_original_count(n_source_symbols),
            Self::reed_solomon_recovery_count(n_source_symbols, n_shards),
            Self::reed_solomon_shard_bytes(symbol_size),
        )
        .map_err(|e| EncodeError::IncompatibleParameters(e.to_string()))?;

        Ok(Self {
            encoder,
            n_source_symbols,
            n_shards,
            symbol_size,
            encoded_symbols: None,
        })
    }

    pub(super) fn check_parameters_and_compute_symbol_size(
        data_length: usize,
        n_source_symbols: NonZeroU16,
    ) -> Result<NonZeroU16, EncodeError> {
        if data_length == 0 {
            return Err(InvalidDataSizeError::EmptyData.into());
        }
        let symbol_size = utils::compute_symbol_size_from_usize(
            data_length,
            n_source_symbols.into(),
            Self::ASSOCIATED_ENCODING_TYPE.required_alignment(),
        )
        .map_err(InvalidDataSizeError::from)?;
        let expected_length = usize::from(n_source_symbols.get()) * usize::from(symbol_size.get());
        if data_length != expected_length {
            return Err(EncodeError::IncorrectDataLength(expected_length));
        }
        Ok(symbol_size)
    }

    /// Returns a reference to a [`Symbols`] object containing all `n_shards` source and repair
    /// symbols for the provided data.
    ///
    /// # Errors
    ///
    /// Returns an [`EncodeError::IncorrectDataLength`] if the length of the data is not equal to
    /// the product of the number of source symbols and the symbol size.
    pub fn encode_all_ref<'a>(&'a mut self, data: &'_ [u8]) -> Result<&'a Symbols, EncodeError> {
        let result = self.encode_all(data)?;
        Ok(self.set_and_return_encoded_symbols(result))
    }

    /// Returns a reference to a [`Symbols`] object containing all `n_shards` source and repair
    /// symbols for the provided data.
    ///
    /// # Errors
    ///
    /// Returns an [`EncodeError::IncorrectDataLength`] if the length of the data is not equal to
    /// the product of the number of source symbols and the symbol size.
    pub fn encode_all(&mut self, data: &[u8]) -> Result<Symbols, EncodeError> {
        let mut result = self.take_or_create_encoded_symbols(self.n_shards.get().into());
        self.check_data_length(data)?;
        assert_eq!(
            result.symbol_size(),
            self.symbol_size,
            "result buffer must have the same symbol size as the encoder"
        );

        result
            .extend(data)
            .expect("cannot fail as we have checked the length of the data");
        self.encode_all_repair_symbols_inner(&mut result, data)?;

        Ok(result)
    }

    fn encode_all_repair_symbols_inner(
        &mut self,
        result_buffer: &mut Symbols,
        data: &[u8],
    ) -> Result<(), EncodeError> {
        self.check_data_length(data)?;
        assert_eq!(
            result_buffer.symbol_size(),
            self.symbol_size,
            "result buffer must have the same symbol size as the encoder"
        );

        for symbol in self.encode(data)?.recovery_iter() {
            result_buffer
                .extend(symbol)
                .expect("the encoded symbols definitely have the correct size");
        }

        Ok(())
    }

    fn take_or_create_encoded_symbols(&mut self, required_capacity: usize) -> Symbols {
        match self.encoded_symbols.take() {
            Some(mut symbols) => {
                symbols.truncate(0);
                symbols.set_min_capacity(required_capacity);
                symbols
            }
            None => Symbols::with_capacity(required_capacity, self.symbol_size),
        }
    }

    fn set_and_return_encoded_symbols(&mut self, symbols: Symbols) -> &Symbols {
        self.encoded_symbols = Some(symbols);
        self.encoded_symbols
            .as_ref()
            .expect("we have just set the encoded symbols")
    }

    fn check_data_length(&self, data: &[u8]) -> Result<(), EncodeError> {
        let expected_length =
            usize::from(self.n_source_symbols.get()) * usize::from(self.symbol_size.get());
        ensure!(
            data.len() == expected_length,
            EncodeError::IncorrectDataLength(expected_length),
        );
        Ok(())
    }

    pub(crate) fn encode(&mut self, data: &[u8]) -> Result<EncoderResult<'_>, EncodeError> {
        self.check_data_length(data)?;
        self.reset();

        for symbol in data.chunks_exact(self.symbol_size.get().into()) {
            self.encoder
                .add_original_shard(symbol)
                .expect("cannot fail as we have checked the length of the data");
        }

        Ok(self
            .encoder
            .encode()
            .expect("we have added all source symbols, so this cannot fail"))
    }

    fn reset(&mut self) {
        self.encoder
            .reset(
                Self::reed_solomon_original_count(self.n_source_symbols),
                Self::reed_solomon_recovery_count(self.n_source_symbols, self.n_shards),
                Self::reed_solomon_shard_bytes(self.symbol_size),
            )
            .expect("cannot fail as we use the same parameters as when the encoder was created");
    }

    fn reed_solomon_original_count(n_source_symbols: NonZeroU16) -> usize {
        n_source_symbols.get().into()
    }

    fn reed_solomon_recovery_count(n_source_symbols: NonZeroU16, n_shards: NonZeroU16) -> usize {
        (n_shards.get() - n_source_symbols.get()).into()
    }

    fn reed_solomon_shard_bytes(symbol_size: NonZeroU16) -> usize {
        symbol_size.get().into()
    }
}
