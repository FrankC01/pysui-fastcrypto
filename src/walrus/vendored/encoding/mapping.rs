// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/encoding/mapping.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Upstream `#[cfg(test)]` code omitted. All other items are copied verbatim.

//! The mapping between the encoded sliver pairs and shards.

use core::num::NonZeroU16;

use thiserror::Error;

use super::SliverPair;
use crate::walrus::vendored::core::{BlobId, ShardIndex, SliverPairIndex};

/// Errors returned if the slice of sliver pairs has already been shuffled in a way that is
/// inconsistent with the provided blob id.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SliverAssignmentError {
    /// The rotation is inconsistent with respect to the blob id.
    #[error("the sliver pairs are already rotated, but not according to the blob id")]
    InconsistentRotation,
    /// The input slice of pairs is not a valid rotation.
    #[error("the sliver pairs have been incorrectly shuffled")]
    InvalidInputOrder,
}

/// Rotate the slice of sliver pairs in place, based on the rotation specified by the blob ID.
///
/// Does nothing if the `pairs` have already been rotated correctly, according to the blob ID.
/// Returns a [`SliverAssignmentError`] if the slice is shuffled in a way that is inconsistent with
/// the provided `blob_id`.
///
/// The `blob_id` -- which is typically the blob ID of the blob that produced the sliver pairs -- is
/// interpreted as a big-endian unsigned integer, and is then used to compute the amount for which
/// to rotate the slice. The rotation is such that the last `blob_id % slice.len()` elements of the
/// slice move to the front.
///
/// # Errors
///
/// Returns a [`SliverAssignmentError`] if the `pairs` have already been shuffled in a way that is
/// inconsistent with the provided `blob_id`.
///
/// # Panics
///
/// Panics if the length of the provided slice is larger than `u16::MAX`.
pub fn rotate_pairs(
    pairs: &mut [SliverPair],
    blob_id: &BlobId,
) -> Result<(), SliverAssignmentError> {
    let Some(n_pairs) = NonZeroU16::new(
        pairs
            .len()
            .try_into()
            .expect("there must not be more than `u16::MAX` sliver pairs"),
    ) else {
        // Nothing to do for an empty slice.
        return Ok(());
    };
    if is_rotation(pairs) {
        if pairs[0].index() == SliverPairIndex(0) {
            rotate_by_bytes(pairs, blob_id.as_ref());
        } else if pairs[0].index() != ShardIndex(0).to_pair_index(n_pairs, blob_id) {
            return Err(SliverAssignmentError::InconsistentRotation);
        }
        Ok(())
    } else {
        Err(SliverAssignmentError::InvalidInputOrder)
    }
}

/// Rotate the slice of sliver pairs in place, based on the rotation specified by the blob ID.
///
/// This function does not check whether the pairs have already been rotated. See [`rotate_pairs`]
/// for the checked version and the details on how the rotation is performed.
pub fn rotate_pairs_unchecked(pairs: &mut [SliverPair], blob_id: &BlobId) {
    if pairs.is_empty() {
        return;
    }
    rotate_by_bytes(pairs, blob_id.as_ref());
}

/// Check that the slice of sliver pairs is a valid rotation.
///
/// This only checks the first sliver of the pair, it does not check the internal state of the pair.
fn is_rotation(pairs: &[SliverPair]) -> bool {
    pairs.iter().enumerate().all(|(index, pair)| {
        pair.index().as_usize() == (index + pairs[0].index().as_usize()) % pairs.len()
    })
}

impl SliverPairIndex {
    /// Returns the index of the shard on which the sliver pair with this index is stored.
    ///
    /// The mapping depends on the total number of shards, `n_shards`, and the blob ID to which this
    /// sliver corresponds, `blob_id`. The `blob_id` is interpreted as a big-endian unsigned
    /// integer, and then used to compute the offset for the sliver pair index.
    pub fn to_shard_index(&self, n_shards: NonZeroU16, blob_id: &BlobId) -> ShardIndex {
        ((self.as_usize() + rotation_offset(n_shards, blob_id)) % usize::from(n_shards.get()))
            .try_into()
            .expect("definitely fits into a u16 because `n_shards` is a u16")
    }
}

impl ShardIndex {
    /// Returns the index of the sliver pair of this blob corresponding to this shard index.
    ///
    /// This is the reverse operation of [`SliverPairIndex::to_shard_index`].
    pub fn to_pair_index(&self, n_shards: NonZeroU16, blob_id: &BlobId) -> SliverPairIndex {
        let n_shards_usize = usize::from(n_shards.get());
        ((n_shards_usize + self.as_usize() - rotation_offset(n_shards, blob_id)) % n_shards_usize)
            .try_into()
            .expect("definitely fits into a u16 because `n_shards` is a u16")
    }
}

fn rotation_offset(n_shards: NonZeroU16, blob_id: &BlobId) -> usize {
    bytes_mod(blob_id.as_ref(), n_shards.get().into())
}

/// Rotate the input `slice` in place, based on the rotation specified by the `rotation` byte array.
///
/// The `rotation` byte array is the amount for which to rotate the slice, and it is interpreted as
/// a big-endian unsigned integer. The `rotation` will typically be the blob ID. The resulting
/// rotation of the slice is such that the last `rotation % slice.len()` elements of the slice move
/// to the front.
fn rotate_by_bytes<T>(slice: &mut [T], rotation: &[u8]) {
    slice.rotate_right(bytes_mod(rotation, slice.len()))
}

/// Compute the modulo of the input byte array interpreted as an big-endian unsigned integer.
///
/// Uses Horner's method.
fn bytes_mod(bytes: &[u8], modulus: usize) -> usize {
    bytes
        .iter()
        .fold(0, |acc, &byte| (acc * 256 + usize::from(byte)) % modulus)
}
