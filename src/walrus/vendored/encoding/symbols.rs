// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/encoding/symbols.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Encode path only. All decoding/recovery symbol types are omitted.
//   * Upstream is `#![no_std]` and imports from `alloc`; this crate is std,
//     so those imports are dropped.
//   * Upstream `#[cfg(test)]` code omitted.

//! Symbol storage for RedStuff encoding, vendored from walrus-core.

use core::num::NonZeroU16;
use core::ops::{Index, IndexMut};
use core::slice::{Chunks, ChunksMut};

use serde::{Deserialize, Serialize};
use serde_with::{Bytes, serde_as};

use super::WrongSymbolSizeError;

/// A set of encoded symbols.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbols {
    /// The encoded symbols.
    // INV: The length of this vector is a multiple of `symbol_size`.
    #[serde_as(as = "Bytes")]
    data: Vec<u8>,
    /// The number of bytes for each symbol.
    symbol_size: NonZeroU16,
}

impl Symbols {
    /// Creates a new [`Symbols`] struct by taking ownership of a vector.
    ///
    /// # Panics
    ///
    /// Panics if the `data` does not contain complete symbols, i.e., if
    /// `data.len() % symbol_size != 0`.
    pub fn new(data: Vec<u8>, symbol_size: NonZeroU16) -> Self {
        assert!(
            data.len().is_multiple_of(usize::from(symbol_size.get())),
            "the provided data must contain complete symbols"
        );
        Symbols { data, symbol_size }
    }

    /// Shortens the `data` in [`Symbols`], keeping the first `len` symbols and dropping the
    /// rest. If `len` is greater or equal to the [`Symbols`]' current number of symbols, this has
    /// no effect.
    pub fn truncate(&mut self, len: usize) {
        self.data
            .truncate(len * usize::from(self.symbol_size.get()));
    }

    /// Creates a new [`Symbols`] struct with zeroed-out data of length `n_symbols * symbol_size`.
    pub fn zeros(n_symbols: usize, symbol_size: NonZeroU16) -> Self {
        Symbols {
            data: vec![0; n_symbols * usize::from(symbol_size.get())],
            symbol_size,
        }
    }

    /// Creates a new empty [`Symbols`] struct with an internal vector of provided capacity.
    ///
    /// # Examples
    ///
    /// ```
    /// # use walrus_core::encoding::Symbols;
    /// #
    /// assert!(Symbols::with_capacity(42, 1.try_into().unwrap()).is_empty());
    /// ```
    pub fn with_capacity(n_symbols: usize, symbol_size: NonZeroU16) -> Self {
        Symbols {
            data: Vec::<u8>::with_capacity(n_symbols * usize::from(symbol_size.get())),
            symbol_size,
        }
    }

    /// Reserves capacity for at least a total of `min_capacity` symbols.
    pub fn set_min_capacity(&mut self, min_capacity: usize) {
        let current_data_capacity = self.data.capacity();
        self.data
            .reserve((min_capacity * self.symbol_usize()).saturating_sub(current_data_capacity));
    }

    /// Returns an iterator of references to symbols.
    #[inline]
    pub fn to_symbols(&self) -> Chunks<'_, u8> {
        self.data.chunks(self.symbol_usize())
    }

    /// Returns an iterator of mutable references to symbols.
    #[inline]
    pub fn to_symbols_mut(&mut self) -> ChunksMut<'_, u8> {
        let symbol_size = self.symbol_usize();
        self.data.chunks_mut(symbol_size)
    }

    /// Add one or more symbols to the collection.
    ///
    /// # Errors
    ///
    /// Returns a [`WrongSymbolSizeError`] error if the provided symbols do not match the
    /// `symbol_size` of the struct.
    #[inline]
    pub fn extend(&mut self, symbols: &[u8]) -> Result<(), WrongSymbolSizeError> {
        if !symbols.len().is_multiple_of(self.symbol_usize()) {
            return Err(WrongSymbolSizeError);
        }
        self.data.extend(symbols);
        Ok(())
    }

    /// Returns the `symbol_size`.
    #[inline]
    pub fn symbol_size(&self) -> NonZeroU16 {
        self.symbol_size
    }

    /// Returns the `symbol_size` as a `usize`.
    #[inline]
    pub fn symbol_usize(&self) -> usize {
        self.symbol_size.get().into()
    }

    /// Returns a reference to the inner vector of `data` representing the symbols.
    #[inline]
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    /// Returns a mutable reference to the inner vector of `data` representing the symbols.
    #[inline]
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    /// Returns the range of the underlying byte vector that contains the symbols in the range.
    #[inline]
    pub fn symbol_range(&self, range: core::ops::Range<usize>) -> core::ops::Range<usize> {
        self.symbol_usize() * range.start..self.symbol_usize() * range.end
    }
}

impl Index<usize> for Symbols {
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[self.symbol_range(index..index + 1)]
    }
}

impl IndexMut<usize> for Symbols {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let range = self.symbol_range(index..index + 1);
        &mut self.data[range]
    }
}
