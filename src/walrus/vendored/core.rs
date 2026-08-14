// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/lib.rs` (crate-root items)
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Named `core.rs` because upstream's items live in the crate root
//     `lib.rs`, which cannot be mirrored as a file inside a module dir.
//   * Encode path only.
//   * `BlobId::from_sliver_pair_metadata` omits upstream's `tracing::debug!`
//     call; the surrounding `let blob_id = ...` binding is kept verbatim so the
//     body stays diffable against upstream.
//   * `Display for BlobId` uses `base64ct::Base64UrlUnpadded` instead of
//     upstream's `base64` crate, to avoid an additional dependency.
//     `base64ct` is already a dependency of this crate. Output must be
//     byte-identical; this is verified by the upstream blob-ID golden vector.
//   * `#[macro_export]` removed from `index_type!` and `ensure!`; replaced
//     with `pub(crate) use` so they stay internal to this crate.
//   * Upstream is `#![no_std]` and imports from `alloc`; this crate is std,
//     so those imports are dropped.
//   * `EncodingAxis` is imported from `vendored::encoding`, matching upstream
//     where `lib.rs` imports it from the `encoding` module.
//   * Upstream `#[cfg(test)]` code omitted.

//! Core Walrus types — blob IDs, sliver indices and encoding types.
//! Vendored from walrus-core's crate root.

use core::{
    fmt::{self, Debug, Display},
    num::NonZeroU16,
    str::FromStr,
};

use base64ct::{Base64UrlUnpadded, Encoding};
use fastcrypto::hash::{Blake2b256, HashFunction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::walrus::vendored::encoding::EncodingAxis;
use crate::walrus::vendored::merkle::Node;
use crate::walrus::vendored::metadata::{BlobMetadata, BlobMetadataApi as _};
use crate::walrus::vendored::utils::wrapped_uint;

/// Returns an error if the condition evaluates to false.
///
/// Instead of an error, a message can be provided as a single string literal or as a format string
/// with additional parameters. In those cases, the message is turned into an error using
/// anyhow and then converted to the expected type.
///
/// # Examples
///
/// ```
/// # use thiserror::Error;
/// # use walrus_core::ensure;
/// #
/// # #[derive(Debug, Error, PartialEq)]
/// #[error("some error has occurred")]
/// struct MyError;
///
/// let function = |condition: bool| -> Result::<usize, MyError> {
///     ensure!(condition, MyError);
///     Ok(42)
/// };
/// assert_eq!(function(true).unwrap(), 42);
/// assert_eq!(function(false).unwrap_err(), MyError);
/// ```
///
/// ```
/// # use anyhow;
/// # use walrus_core::ensure;
/// let function = |condition: bool| -> anyhow::Result::<()> {
///     ensure!(condition, "some error message");
///     Ok(())
/// };
/// assert!(function(true).is_ok());
/// assert_eq!(function(false).unwrap_err().to_string(), "some error message");
/// ```
macro_rules! ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return Err(anyhow::anyhow!($msg).into());
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return Err(anyhow::anyhow!($fmt, $($arg)*).into());
        }
    };
}

pub(crate) use ensure;

/// This macro is used to create separate types for specific indices.
///
/// While those could all be represented by the same type (`u16`), having separate types helps
/// finding bugs; for example, when a sliver index is not properly converted to a sliver-pair index.
///
/// The macro adds additional implementations on top of the [`wrapped_uint`] macro.
macro_rules! index_type {
    (
        $(#[$outer:meta])*
        $name:ident($display_prefix:expr)
    ) => {
        wrapped_uint!(
            $(#[$outer])*
            #[derive(Default)]
            pub struct $name(pub u16) {
                /// Returns the index as a `usize`.
                pub fn as_usize(&self) -> usize {
                    self.0.into()
                }

                /// Returns the index as a `u32`.
                pub fn as_u32(&self) -> u32 {
                    self.0.into()
                }

                /// Returns the index as a `u64`.
                pub fn as_u64(&self) -> u64 {
                    self.0.into()
                }
            }
        );

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

pub(crate) use index_type;

/// The epoch number.
pub type Epoch = u32;

// Blob ID.

/// The ID of a blob.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[repr(transparent)]
pub struct BlobId(pub [u8; Self::LENGTH]);

impl BlobId {
    /// The length of a blob ID in bytes.
    pub const LENGTH: usize = 32;

    /// A blob ID with all zeros.
    pub const ZERO: Self = Self([0u8; Self::LENGTH]);

    /// A blob ID with all ones.
    pub const MAX: Self = Self([u8::MAX; Self::LENGTH]);

    /// Returns the blob ID as a hash over the Merkle root, encoding type,
    /// and unencoded_length of the blob.
    pub fn from_metadata(merkle_root: Node, encoding: EncodingType, unencoded_length: u64) -> Self {
        Self::new_with_hash_function::<Blake2b256>(merkle_root, encoding, unencoded_length)
    }

    /// Computes the Merkle root over the [`SliverPairMetadata`][metadata::SliverPairMetadata],
    /// contained in the `blob_metadata` and then computes the blob ID.
    pub fn from_sliver_pair_metadata(blob_metadata: &BlobMetadata) -> Self {
        let merkle_root = blob_metadata.compute_root_hash();
        let blob_id = Self::from_metadata(
            merkle_root,
            blob_metadata.encoding_type(),
            blob_metadata.unencoded_length(),
        );
        blob_id
    }

    /// Extracts the first two bytes of the blob ID as a `u16`, with the left most bit being the
    /// most significant.
    ///
    /// The extracted can be used to monitor the progress of tasks that scans over blob IDs.
    pub fn first_two_bytes(&self) -> u16 {
        u16::from_be_bytes(
            self.0[0..2]
                .try_into()
                .expect("two bytes can be converted to a u16"),
        )
    }

    fn new_with_hash_function<T>(
        merkle_root: Node,
        encoding: EncodingType,
        unencoded_length: u64,
    ) -> BlobId
    where
        T: HashFunction<{ Self::LENGTH }>,
    {
        let mut hasher = T::default();

        // This is equivalent to the bcs encoding of the encoding type,
        // unencoded length, and merkle root.
        hasher.update([encoding.into()]);
        hasher.update(unencoded_length.to_le_bytes());
        hasher.update(merkle_root.bytes());

        Self(hasher.finalize().into())
    }
}

impl AsRef<[u8]> for BlobId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Base64UrlUnpadded::encode_string(self.as_ref()))
    }
}

impl Debug for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobId({self})")
    }
}

/// Error returned when unable to parse a blob ID.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("failed to parse a blob ID")]
pub struct BlobIdParseError;

impl TryFrom<&[u8]> for BlobId {
    type Error = BlobIdParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; Self::LENGTH]>::try_from(value).map_err(|_| BlobIdParseError)?;
        Ok(Self(bytes))
    }
}

impl FromStr for BlobId {
    type Err = BlobIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = Base64UrlUnpadded::decode_vec(s).map_err(|_| BlobIdParseError)?;
        let bytes = <[u8; Self::LENGTH]>::try_from(decoded.as_slice()).map_err(|_| BlobIdParseError)?;
        Ok(Self(bytes))
    }
}

// Sui Object ID.

/// The ID of a Sui object.
///
/// Reimplemented here to not take a mandatory dependency on the sui sdk in the core crate.
/// With the feature `sui-types` enabled, this type can be converted to and from
/// the `ObjectID` type from the sui sdk.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash, Debug)]
#[repr(transparent)]
pub struct SuiObjectId(pub [u8; Self::LENGTH]);

impl SuiObjectId {
    /// The length of a Sui object ID in bytes.
    pub const LENGTH: usize = 32;
}

/// Error returned when unable to parse a Sui object ID.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("failed to parse a Sui object ID")]
pub struct SuiObjectIdParseError;

impl TryFrom<&[u8]> for SuiObjectId {
    type Error = SuiObjectIdParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; Self::LENGTH]>::try_from(value).map_err(|_| SuiObjectIdParseError)?;
        Ok(Self(bytes))
    }
}

// Sliver and shard indices.

index_type!(
    /// Represents the index of a (primary or secondary) sliver.
    #[derive(Ord, PartialOrd)]
    SliverIndex("sliver")
);

index_type!(
    /// Represents the index of a sliver pair.
    ///
    /// As blobs are encoded into as many pairs of slivers as there are shards in the committee,
    /// this value ranges be from 0 to the number of shards (exclusive).
    #[derive(Ord, PartialOrd)]
    SliverPairIndex("sliver-pair")
);

impl From<SliverIndex> for SliverPairIndex {
    fn from(value: SliverIndex) -> Self {
        Self(value.0)
    }
}

impl From<SliverPairIndex> for SliverIndex {
    fn from(value: SliverPairIndex) -> Self {
        Self(value.0)
    }
}

impl PartialOrd<NonZeroU16> for SliverIndex {
    fn partial_cmp(&self, other: &NonZeroU16) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(&other.get())
    }
}

impl PartialEq<NonZeroU16> for SliverIndex {
    fn eq(&self, other: &NonZeroU16) -> bool {
        self.0.eq(&other.get())
    }
}

impl FromStr for SliverIndex {
    type Err = <u16 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SliverIndex(s.parse()?))
    }
}

impl SliverPairIndex {
    /// Computes the index of the [`Sliver`] of the corresponding axis starting from the index of
    /// the [`SliverPair`][encoding::SliverPair].
    ///
    /// This is needed because primary slivers are assigned in ascending `pair_index` order, while
    /// secondary slivers are assigned in descending `pair_index` order. I.e., the first primary
    /// sliver is contained in the first sliver pair, but the first secondary sliver is contained in
    /// the last sliver pair.
    ///
    /// # Panics
    ///
    /// Panics if the index is greater than or equal to `n_shards`.
    pub fn to_sliver_index<E: EncodingAxis>(self, n_shards: NonZeroU16) -> SliverIndex {
        if E::IS_PRIMARY {
            self.into()
        } else {
            (n_shards.get() - self.0 - 1).into()
        }
    }
}

index_type!(
    /// Represents the index of a shard.
    #[derive(PartialOrd, Ord)]
    ShardIndex("shard")
);

// Encoding Type.

/// Error returned for an invalid conversion to an encoding type.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("the provided value is not a valid EncodingType")]
pub struct InvalidEncodingType;

/// Supported Walrus encoding types.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EncodingType {
    /// RedStuff using the Reed-Solomon erasure code.
    RS2 = 1,
}

impl From<EncodingType> for u8 {
    #[inline]
    fn from(value: EncodingType) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for EncodingType {
    type Error = InvalidEncodingType;

    #[inline]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EncodingType::RS2),
            _ => Err(InvalidEncodingType),
        }
    }
}

impl FromStr for EncodingType {
    type Err = InvalidEncodingType;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "redstuff/reed-solomon" | "rs2" | "reed-solomon" => Ok(Self::RS2),
            _ => Err(InvalidEncodingType),
        }
    }
}

impl EncodingType {
    /// Returns the required alignment of symbols for the encoding type.
    #[inline]
    pub fn required_alignment(&self) -> u16 {
        match self {
            Self::RS2 => 2,
        }
    }

    /// Returns the maximum size of a symbol for the encoding type.
    #[inline]
    pub fn max_symbol_size(&self) -> u16 {
        match self {
            Self::RS2 => u16::MAX - 1,
        }
    }
}

impl Display for EncodingType {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RS2 => write!(f, "RedStuff/Reed-Solomon"),
        }
    }
}

