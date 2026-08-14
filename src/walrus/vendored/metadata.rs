// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/metadata.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Encode path only. All quilt types, verification helpers and decode-side
//     accessors are omitted.
//   * `trait BlobMetadataApi` is reduced to the four members the encode path
//     uses (`compute_root_hash`, `encoding_type`, `unencoded_length`,
//     `hashes`). `get_sliver_hash`, `symbol_size` and `encoded_size` are
//     omitted, and correspondingly omitted from
//     `impl BlobMetadataApi for BlobMetadataV1`. This mirrors the
//     `EncodingFactory` member-subset precedent in `encoding/config.rs`.
//   * Upstream is `#![no_std]` and imports from `alloc`; this crate is std,
//     so those imports are dropped.
//   * Upstream `#[cfg(test)]` code omitted.

//! Blob metadata types for RedStuff encoding, vendored from walrus-core.

use core::fmt::Debug;

use enum_dispatch::enum_dispatch;
use fastcrypto::hash::{Blake2b256, HashFunction};
use serde::{Deserialize, Serialize};

use crate::walrus::vendored::{
    core::{BlobId, EncodingType},
    merkle::{DIGEST_LEN, MerkleTree, Node as MerkleNode},
};

/// [`BlobMetadataWithId`] that has been verified with [`UnverifiedBlobMetadataWithId::verify`].
///
/// This ensures the following properties:
/// - The unencoded length is nonzero and not larger than the maximum blob size.
/// - The number of sliver hashes matches the number of slivers (twice the number of shards).
/// - The blob ID is correctly computed from the sliver hashes.
pub type VerifiedBlobMetadataWithId = BlobMetadataWithId<true>;

/// Metadata associated with a blob.
///
/// Stores the [`BlobId`] as well as additional details such as the encoding type,
/// unencoded length of the blob, and the hashes associated the slivers.
/// See [`VerifiedBlobMetadataWithId`] and [`UnverifiedBlobMetadataWithId`] for the details
/// about the V type variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobMetadataWithId<const V: bool = false> {
    blob_id: BlobId,
    metadata: BlobMetadata,
}

impl<const V: bool> BlobMetadataWithId<V> {
    /// Creates a new verified metadata starting from the components of the metadata.
    ///
    /// The verification is implicit as the blob ID is created directly from the metadata.
    pub fn new_verified_from_metadata(
        sliver_pair_meta: Vec<SliverPairMetadata>,
        encoding: EncodingType,
        unencoded_length: u64,
    ) -> VerifiedBlobMetadataWithId {
        let blob_metadata = BlobMetadata::new(encoding, unencoded_length, sliver_pair_meta);
        Self::new_verified_unchecked(
            BlobId::from_sliver_pair_metadata(&blob_metadata),
            blob_metadata,
        )
    }

    /// Creates a new verified metadata with the corresponding blob ID, without running the
    /// verification.
    pub fn new_verified_unchecked(
        blob_id: BlobId,
        metadata: BlobMetadata,
    ) -> VerifiedBlobMetadataWithId {
        BlobMetadataWithId { blob_id, metadata }
    }

    /// The ID of the blob associated with the metadata.
    pub fn blob_id(&self) -> &BlobId {
        &self.blob_id
    }

    /// The associated [`BlobMetadata`].
    pub fn metadata(&self) -> &BlobMetadata {
        &self.metadata
    }
}

/// Trait for the API of [`BlobMetadata`].
#[enum_dispatch]
pub trait BlobMetadataApi {
    /// Returns the root hash of the Merkle tree over the sliver pairs.
    fn compute_root_hash(&self) -> MerkleNode;

    /// Returns the encoding type of the blob.
    fn encoding_type(&self) -> EncodingType;

    /// Returns the unencoded length of the blob.
    fn unencoded_length(&self) -> u64;

    /// Returns the hashes of the sliver pairs of the blob.
    fn hashes(&self) -> &Vec<SliverPairMetadata>;
}

/// Metadata about a blob.
#[enum_dispatch(BlobMetadataApi)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobMetadata {
    /// Version 1 of the blob metadata.
    V1(BlobMetadataV1),
}

impl BlobMetadata {
    /// Creates a new [`BlobMetadata`] with the given encoding type, unencoded length, and sliver
    /// hashes.
    pub fn new(
        encoding_type: EncodingType,
        unencoded_length: u64,
        hashes: Vec<SliverPairMetadata>,
    ) -> BlobMetadata {
        BlobMetadata::V1(BlobMetadataV1 {
            encoding_type,
            unencoded_length,
            hashes,
        })
    }

    /// Returns the encoding type of the blob.
    pub fn encoding_type(&self) -> EncodingType {
        match self {
            BlobMetadata::V1(inner) => inner.encoding_type,
        }
    }
}

/// Metadata about a blob, without its corresponding [`BlobId`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobMetadataV1 {
    /// The type of encoding used to erasure encode the blob.
    pub encoding_type: EncodingType,
    /// The length of the unencoded blob.
    pub unencoded_length: u64,
    /// The hashes over the slivers of the blob.
    pub hashes: Vec<SliverPairMetadata>,
}

impl Debug for BlobMetadataV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlobMetadataV1")
            .field("encoding_type", &self.encoding_type)
            .field("unencoded_length", &self.unencoded_length)
            .field("hashes_count", &self.hashes.len())
            .finish()
    }
}

impl BlobMetadataApi for BlobMetadataV1 {
    /// Returns the root hash of the Merkle tree over the sliver pairs.
    fn compute_root_hash(&self) -> MerkleNode {
        MerkleTree::<Blake2b256>::build(
            self.hashes
                .iter()
                .map(|h| h.pair_leaf_input::<Blake2b256>()),
        )
        .root()
    }

    fn encoding_type(&self) -> EncodingType {
        self.encoding_type
    }

    fn unencoded_length(&self) -> u64 {
        self.unencoded_length
    }

    fn hashes(&self) -> &Vec<SliverPairMetadata> {
        &self.hashes
    }
}

/// Metadata about a sliver pair, i.e., the root hashes of the primary and secondary slivers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliverPairMetadata {
    /// The hash of the primary sliver in the sliver pair.
    pub primary_hash: MerkleNode,
    /// The hash of the secondary sliver in the sliver pair.
    pub secondary_hash: MerkleNode,
}

impl SliverPairMetadata {
    /// Concatenates the Merkle roots over the primary and secondary slivers.
    ///
    /// This is then to be used as input to compute the Merkle tree over the sliver pairs.
    pub fn pair_leaf_input<T: HashFunction<DIGEST_LEN>>(&self) -> [u8; 2 * DIGEST_LEN] {
        let mut concat = [0u8; 2 * DIGEST_LEN];
        concat[0..DIGEST_LEN].copy_from_slice(&self.primary_hash.bytes());
        concat[DIGEST_LEN..2 * DIGEST_LEN].copy_from_slice(&self.secondary_hash.bytes());
        concat
    }
}
