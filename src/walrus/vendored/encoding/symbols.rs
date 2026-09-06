// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/encoding/symbols.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Encode and decode paths. `DecodingSymbol` is vendored; the recovery
//     symbol types (`EitherDecodingSymbol`, `GeneralRecoverySymbol`,
//     `RecoverySymbol`, `RecoverySymbolPair`) remain omitted.
//   * `DecodingSymbol::with_proof` is omitted — it returns a `RecoverySymbol`,
//     which is not vendored.
//   * `Symbols::len`, `Symbols::is_empty`, `Symbols::into_vec` and the
//     `Index`/`IndexMut` impls over `Range<usize>` are restored — all four were
//     trimmed as encode-unused but are required by the decode path.
//     `AsRef<[u8]> for Symbols` remains omitted.
//   * `Display for DecodingSymbol` is omitted, matching the treatment of
//     `Display for SliverData` in `slivers.rs`.
//   * Upstream is `#![no_std]` and imports from `alloc`; this crate is std,
//     so those imports are dropped.
//   * Upstream `#[cfg(test)]` code omitted.

//! Symbol storage for RedStuff encoding, vendored from walrus-core.

use core::marker::PhantomData;
use core::num::NonZeroU16;
use core::ops::{Index, IndexMut, Range};
use core::slice::{Chunks, ChunksMut};

use serde::{Deserialize, Serialize};
use serde_with::{Bytes, serde_as};

use super::{EncodingAxis, WrongSymbolSizeError};

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

    /// The number of symbols.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len() / self.symbol_usize()
    }

    /// True iff it does not contain any symbols.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
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

    /// Returns the underlying byte vector as an owned object.
    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.data
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

impl Index<Range<usize>> for Symbols {
    type Output = [u8];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.data[self.symbol_range(index)]
    }
}

impl IndexMut<Range<usize>> for Symbols {
    fn index_mut(&mut self, index: Range<usize>) -> &mut Self::Output {
        let range = self.symbol_range(index);
        &mut self.data[range]
    }
}

/// A single symbol used for decoding, consisting of the data and the symbol's index.
///
/// The type parameter `T` represents the [`EncodingAxis`] of the sliver that can be recovered from
/// this symbol.  I.e., a [`DecodingSymbol<Primary>`] is used to recover a
/// [`Sliver<Primary>`][super::slivers::SliverData<Primary>].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodingSymbol<T> {
    /// The index of the symbol.
    ///
    /// This is equal to the ESI as defined in [RFC 6330][rfc6330s5.3.1].
    ///
    /// [rfc6330s5.3.1]: https://datatracker.ietf.org/doc/html/rfc6330#section-5.3.1
    pub index: u16,
    /// The symbol data as a byte vector.
    pub data: Vec<u8>,
    /// Marker representing whether this symbol is used to decode primary or secondary slivers.
    _axis: PhantomData<T>,
}

impl<T: EncodingAxis> DecodingSymbol<T> {
    /// Returns the symbol size in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true iff the symbol size is 0.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<T: EncodingAxis> DecodingSymbol<T> {
    /// Creates a new `DecodingSymbol`.
    pub fn new(index: u16, data: Vec<u8>) -> Self {
        Self {
            index,
            data,
            _axis: PhantomData,
        }
    }
}
