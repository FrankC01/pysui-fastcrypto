//    Copyright Frank V. Castellucci
//    SPDX-License-Identifier: Apache-2.0

//! RedStuff encoding, vendored from `walrus-core/src/encoding/`.
//!
//! Encode path only — decode, recovery and quilt support are omitted.

mod basic_encoding;
pub use basic_encoding::ReedSolomonEncoder;

mod blob_encoding;
pub use blob_encoding::{BlobEncoder, OwnedOrBorrowedBlob};

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
    EncodeError,
    InvalidDataSizeError,
    WrongSymbolSizeError,
};

mod mapping;
pub use mapping::{SliverAssignmentError, rotate_pairs, rotate_pairs_unchecked};

mod slivers;
pub use slivers::{PrimarySliver, SecondarySliver, SliverData, SliverPair};

mod symbols;
pub use symbols::Symbols;

mod utils;
