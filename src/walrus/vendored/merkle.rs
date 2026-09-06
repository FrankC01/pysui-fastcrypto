// Copyright (c) Walrus Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from walrus-core `src/merkle.rs`
// Upstream: https://github.com/MystenLabs/walrus
// Commit:   14641cc0edcc727825d07aa19df2eef8046a3c0d
//
// Modifications Copyright Frank V. Castellucci:
//   * Encode and verification paths. `MerkleTree::build` backs decode-time
//     checks too, via `SliverData::verify` and `BlobMetadataWithId::verify`.
//     Merkle PROOF support is omitted: `MerkleProof`,
//     `MerkleProofError`, the `MerkleAuth` trait, `verify_root`, `get_proof`
//     and `path_length` are not vendored.
//   * Upstream is `#![no_std]` and imports from `alloc`; this crate is std,
//     so those imports are dropped.
//   * Upstream `#[cfg(test)]` code omitted.

//! Merkle tree construction over Blake2b-256, vendored from walrus-core.

use core::marker::PhantomData;

use fastcrypto::hash::{Blake2b256, Digest, HashFunction};
use serde::{Deserialize, Serialize};

/// The length of the digests used in the merkle tree.
pub const DIGEST_LEN: usize = 32;

const LEAF_PREFIX: [u8; 1] = [0];
const INNER_PREFIX: [u8; 1] = [1];
const EMPTY_NODE: [u8; DIGEST_LEN] = [0; DIGEST_LEN];

/// A node in the Merkle tree.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum Node {
    /// A node with an empty subtree.
    Empty,
    /// A node with children, hash value of length 32 bytes.
    Digest([u8; DIGEST_LEN]),
}

impl Node {
    /// Get the byte representation of [`self`].
    pub fn bytes(&self) -> [u8; DIGEST_LEN] {
        match self {
            Node::Empty => EMPTY_NODE,
            Node::Digest(val) => *val,
        }
    }
}

impl From<Digest<DIGEST_LEN>> for Node {
    fn from(value: Digest<DIGEST_LEN>) -> Self {
        Self::Digest(value.digest)
    }
}

impl AsRef<[u8]> for Node {
    fn as_ref(&self) -> &[u8] {
        match self {
            Node::Empty => EMPTY_NODE.as_ref(),
            Node::Digest(val) => val.as_ref(),
        }
    }
}

/// Merkle tree using a hash function `T` (default: [`Blake2b256`]) from the [`fastcrypto`] crate.
///
/// The data of the leaves is prefixed with `0x00` before hashing and hashes of inner nodes are
/// computed over the concatenation of their children prefixed with `0x01`. Hashes of empty
/// subtrees (i.e. subtrees without data at their leaves) are replaced with all zeros.
#[derive(Serialize, Deserialize)]
pub struct MerkleTree<T = Blake2b256> {
    _hash_type: PhantomData<T>,
    // The nodes of the Merkle tree are stored in a vector level by level starting with
    // the leaf hashes.
    nodes: Vec<Node>,
    n_leaves: usize,
}

impl<T> core::fmt::Debug for MerkleTree<T> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt.debug_struct(&format!("MerkleTree<{}>", core::any::type_name::<T>()))
            .field("nodes", &self.nodes)
            .field("n_leaves", &self.n_leaves)
            .finish()
    }
}

impl<T> MerkleTree<T>
where
    T: HashFunction<DIGEST_LEN>,
{
    /// Create the [`MerkleTree`] as a commitment to the provided data.
    pub fn build<I>(iter: I) -> Self
    where
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator,
        I::Item: AsRef<[u8]>,
    {
        Self::build_from_leaf_hashes(iter.into_iter().map(|leaf| leaf_hash::<T>(leaf.as_ref())))
    }

    /// Create the [`MerkleTree`] as a commitment to the provided data hashes.
    pub fn build_from_leaf_hashes<I>(iter: I) -> Self
    where
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator<Item = Node>,
    {
        let iter = iter.into_iter();

        // Create the capacity that we know will be needed, since the vec will be
        // reused by the call to from_leaf_nodes.
        let mut nodes = Vec::with_capacity(n_nodes(iter.len()));
        nodes.extend(iter);

        let n_leaves = nodes.len();
        let mut level_nodes = n_leaves;
        let mut prev_level_index = 0;

        // Fill all other nodes of the Merkle Tree
        while level_nodes > 1 {
            if level_nodes % 2 == 1 {
                // We need an empty sibling for the last node on the previous level
                nodes.push(Node::Empty);
                level_nodes += 1;
            }

            let new_level_index = prev_level_index + level_nodes;

            (prev_level_index..new_level_index)
                .step_by(2)
                .for_each(|index| nodes.push(inner_hash::<T>(&nodes[index], &nodes[index + 1])));

            prev_level_index = new_level_index;
            level_nodes /= 2;
        }

        Self {
            nodes,
            n_leaves,
            _hash_type: PhantomData,
        }
    }

    /// Get a copy of the root hash of `self`.
    pub fn root(&self) -> Node {
        self.nodes.last().map_or(Node::Empty, |val| val.clone())
    }
}

/// Computes the hash of the provided input to be used as a leaf hash of a Merkle tree.
pub(crate) fn leaf_hash<T>(input: &[u8]) -> Node
where
    T: HashFunction<DIGEST_LEN>,
{
    let mut hash_fun = T::default();
    hash_fun.update(LEAF_PREFIX);
    hash_fun.update(input);
    hash_fun.finalize().into()
}

fn inner_hash<T>(left: &Node, right: &Node) -> Node
where
    T: HashFunction<DIGEST_LEN>,
{
    let mut hash_fun = T::default();
    hash_fun.update(INNER_PREFIX);
    hash_fun.update(left.bytes());
    hash_fun.update(right.bytes());
    hash_fun.finalize().into()
}

fn n_nodes(n_leaves: usize) -> usize {
    let mut lvl_nodes = n_leaves;
    let mut tot_nodes = 0;
    while lvl_nodes > 1 {
        lvl_nodes += lvl_nodes % 2;
        tot_nodes += lvl_nodes;
        lvl_nodes /= 2;
    }
    tot_nodes + lvl_nodes
}
