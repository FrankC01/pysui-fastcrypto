//    Copyright Frank V. Castellucci
//    SPDX-License-Identifier: Apache-2.0

//! RedStuff encoding, vendored from `walrus-core/src/encoding/`.
//!
//! Encode, decode and sliver-verification paths. Sliver recovery and quilt
//! support are omitted; see each vendored file's header for the per-file list
//! of omissions and deviations.

mod basic_encoding;
pub use basic_encoding::{Decoder, ReedSolomonDecoder, ReedSolomonEncoder};

mod blob_encoding;
pub use blob_encoding::{BlobDecoder, BlobEncoder, OwnedOrBorrowedBlob};

mod common;
pub use common::{EncodingAxis, Primary, Secondary};

mod config;
pub use config::{
    EncodingConfig,
    EncodingConfigEnum,
    EncodingFactory,
    MAX_SOURCE_SYMBOLS,
    ReedSolomonEncodingConfig,
    source_symbols_for_n_shards,
};

mod errors;
pub use errors::{
    DataTooLargeError,
    DecodeError,
    EncodeError,
    InvalidDataSizeError,
    RecoverySymbolError,
    SliverVerificationError,
    WrongSymbolSizeError,
};

mod mapping;
pub use mapping::{SliverAssignmentError, rotate_pairs, rotate_pairs_unchecked};

mod slivers;
pub use slivers::{PrimarySliver, SecondarySliver, SliverData, SliverPair};

mod symbols;
pub use symbols::{DecodingSymbol, Symbols};

mod utils;
