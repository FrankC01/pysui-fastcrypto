//    Copyright Frank V. Castellucci
//    SPDX-License-Identifier: Apache-2.0

// -*- coding: utf-8 -*-

//! Correctness gates for the vendored walrus code.
//!
//! Every expected value in this file was authored UPSTREAM and is traceable to a
//! specific upstream test at pinned commit `14641cc0`. That distinction is the
//! whole point of these gates: a golden vector generated from this crate's own
//! output would enshrine a transcription error as "correct" and prove nothing.

use std::num::NonZeroU16;

use crate::walrus::vendored::core::{BlobId, Epoch, SuiObjectId};
use crate::walrus::vendored::encoding::ReedSolomonEncodingConfig;
use crate::walrus::vendored::messages::{
    BlobPersistenceType,
    Confirmation,
    IntentAppId,
    IntentType,
    IntentVersion,
};

const EPOCH: Epoch = 21;
const BLOB_ID: BlobId = BlobId([7; 32]);

/// Gate A — the blob ID for a fixed input must match upstream exactly.
///
/// Mirrors `test_v1_blob_id_stability`, upstream
/// `crates/walrus-core/src/encoding/blob_encoding.rs:1227-1244`.
///
/// This is a whole-pipeline oracle. `blob_id` is a Blake2b256 over the encoding
/// byte, the unencoded length, and the Merkle root — and that root is built from
/// symbol hashes produced by the full 2D Reed-Solomon encode. Any error in
/// encoding, symbol ordering, leaf hashing, domain-separation prefixes, Merkle
/// construction or metadata assembly changes this string.
///
/// It also exercises a recorded deviation: this crate's `Display for BlobId`
/// uses `base64ct::Base64UrlUnpadded` where upstream uses the `base64` crate.
/// If that substitution were wrong, this assertion fails.
#[test]
fn gate_a_v1_blob_id_stability() {
    let blob = b"walrus blob id v1 regression test";
    let n_shards = NonZeroU16::new(10).unwrap();
    let config = ReedSolomonEncodingConfig::new(n_shards);
    let encoder = config
        .get_blob_encoder(blob.as_slice())
        .expect("blob encoder");
    let (_sliver_pairs, metadata) = encoder.encode_with_metadata();
    let blob_id = metadata.blob_id();

    assert_eq!(
        format!("{blob_id}"),
        "RcU82Mwf-CFkv1LaI_2qcpANwpGUuG3TMwnVzZxD2kY",
        "blob ID computation diverged from upstream — this would invalidate \
         every on-chain blob ID"
    );
}

/// Gate B (permanent) — the signed confirmation byte layout.
///
/// Mirrors `confirmation_is_correctly_encoded_permanent`, upstream
/// `crates/walrus-core/src/messages/storage_confirmation.rs:117-140`.
///
/// These bytes are what a storage node signs. A layout divergence does not fail
/// locally — it surfaces only as signature verification failing against the
/// network.
#[test]
fn gate_b_confirmation_encoding_permanent() {
    let confirmation = Confirmation::new(EPOCH, BLOB_ID, BlobPersistenceType::Permanent);
    let encoded = bcs::to_bytes(&confirmation).expect("successful encoding");

    assert_eq!(
        encoded[..3],
        [
            IntentType::BLOB_CERT_MSG.0,
            IntentVersion::default().0,
            IntentAppId::STORAGE.0
        ]
    );
    assert_eq!(encoded[3..7], EPOCH.to_le_bytes());
    assert_eq!(
        encoded[7..39],
        bcs::to_bytes(&BLOB_ID).expect("successful encoding")
    );
    assert_eq!(
        encoded[39..],
        // BlobPersistenceType::Permanent should be encoded as 0
        bcs::to_bytes(&0u8).expect("successful encoding")
    );
    assert_eq!(encoded.len(), 40, "permanent confirmation must be 40 bytes");
}

/// Gate B (deletable) — as above, with the trailing object ID.
///
/// Mirrors `confirmation_is_correctly_encoded_deletable`, upstream
/// `crates/walrus-core/src/messages/storage_confirmation.rs:142-171`.
#[test]
fn gate_b_confirmation_encoding_deletable() {
    let object_id = SuiObjectId([42; 32]);
    let confirmation =
        Confirmation::new(EPOCH, BLOB_ID, BlobPersistenceType::Deletable { object_id });
    let encoded = bcs::to_bytes(&confirmation).expect("successful encoding");

    assert_eq!(
        encoded[..3],
        [
            IntentType::BLOB_CERT_MSG.0,
            IntentVersion::default().0,
            IntentAppId::STORAGE.0
        ]
    );
    assert_eq!(encoded[3..7], EPOCH.to_le_bytes());
    assert_eq!(
        encoded[7..39],
        bcs::to_bytes(&BLOB_ID).expect("successful encoding")
    );
    assert_eq!(
        encoded[39..40],
        // BlobPersistenceType::Deletable should be encoded as 1, followed by the object ID
        bcs::to_bytes(&1u8).expect("successful encoding")
    );
    assert_eq!(
        encoded[40..],
        bcs::to_bytes(&object_id).expect("successful encoding")
    );
    assert_eq!(encoded.len(), 72, "deletable confirmation must be 72 bytes");
}
