//    Copyright Frank V. Castellucci
//    SPDX-License-Identifier: Apache-2.0

// -*- coding: utf-8 -*-

//! Correctness gates for the vendored walrus code.
//!
//! No expected value in this file was produced by this crate. That distinction
//! is the whole point of these gates: a golden vector generated from our own
//! output would enshrine a transcription error as "correct" and prove nothing.
//!
//! Expected values come from upstream in one of two ways:
//!
//!  1. Copied from a specific upstream test at pinned commit `14641cc0`. Gates
//!     A, B and C each cite the upstream file and line they mirror.
//!  2. Produced by RUNNING upstream's own code at that pin. Upstream pins no
//!     sliver or metadata bytes anywhere, so the decode gates (D onward) use a
//!     vector dumped from a throwaway git worktree of walrus at `14641cc0`,
//!     encoding gate A's blob at gate A's shard count. That dump prints the
//!     blob ID through upstream's own `Display`, and it equals the string gate
//!     A pins — which is what ties the generated vectors back to an
//!     upstream-authored one.

use std::num::NonZeroU16;

use crate::walrus::vendored::core::{BlobId, EncodingType, Epoch, SuiObjectId};
use crate::walrus::vendored::encoding::{
    DecodeError, EncodingConfig, Primary, ReedSolomonEncodingConfig, Secondary, SliverData,
    SliverVerificationError,
};
use crate::walrus::vendored::messages::{
    BlobPersistenceType, Confirmation, IntentAppId, IntentType, IntentVersion,
};
use crate::walrus::vendored::metadata::{
    BlobMetadata, UnverifiedBlobMetadataWithId, VerifiedBlobMetadataWithId,
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

/// Gate C — the encoding type must serialise to 1 on the wire.
///
/// Mirrors `encoding_type_bcs_serialize`, upstream
/// `crates/walrus-core/src/lib.rs:984-986`.
///
/// `EncodingType` declares `RS2 = 1`, but that is a `repr` discriminant and
/// serde does not read it. A derived impl serialises by variant POSITION, and
/// RS2 is the only variant, so a plain derive emits 0. Upstream avoids this by
/// routing through `EncodingTypeForSerde`, where index 0 is the deprecated
/// RedStuffRaptorQ and index 1 is RS2.
///
/// The original port of this crate dropped that shim. Nothing local failed:
/// blob IDs were unaffected, so gate A still passed. It surfaced only as every
/// testnet storage node rejecting the metadata PUT with 400 "unable to decode
/// request body as BCS".
#[test]
fn gate_c_encoding_type_serializes_to_one() {
    assert_eq!(
        bcs::to_bytes(&EncodingType::RS2).expect("successful encoding"),
        [1],
        "RS2 must serialise to 1; a plain serde derive would emit 0 and every \
         metadata PUT would be rejected by the network"
    );
}

/// Gate C — the encoding type must deserialise from 1.
///
/// Mirrors `encoding_type_bcs_deserialize`, upstream
/// `crates/walrus-core/src/lib.rs:988-993`.
#[test]
fn gate_c_encoding_type_deserializes_from_one() {
    assert_eq!(
        bcs::from_bytes::<EncodingType>(&[1]).expect("successful decoding"),
        EncodingType::RS2
    );
}

/// Gate C — metadata carrying encoding type 0 must be REJECTED.
///
/// Mirrors `deserializing_metadata_with_encoding_type_zero_fails`, upstream
/// `crates/walrus-core/src/metadata.rs:757-775`.
///
/// Upstream wrote a test specifically to guard this failure; the original port
/// of this crate reproduced the bug without porting the guard. Index 0 is the
/// deprecated RedStuffRaptorQ, whose `TryFrom` returns `Err` — which is exactly
/// how a storage node reports our payload as undecodable.
///
/// Offsets here are for the INNER `BlobMetadata`, which is what this crate PUTs
/// and what upstream's node handler is typed on. Upstream's version of this test
/// serialises the `...WithId` wrapper, so its encoding type sits at offset 33
/// (32-byte blob ID + variant tag) where ours sits at offset 1.
#[test]
fn gate_c_metadata_with_encoding_type_zero_is_rejected() {
    let blob = b"walrus blob id v1 regression test";
    let n_shards = NonZeroU16::new(10).unwrap();
    let config = ReedSolomonEncodingConfig::new(n_shards);
    let encoder = config
        .get_blob_encoder(blob.as_slice())
        .expect("blob encoder");
    let (_sliver_pairs, metadata) = encoder.encode_with_metadata();

    let mut bytes = bcs::to_bytes(metadata.metadata()).expect("valid metadata serializes");

    // BCS layout for the inner BlobMetadata: enum variant index (1 byte ULEB128
    // for V1), then BlobMetadataV1.encoding_type (1 byte).
    const VARIANT_OFFSET: usize = 0;
    const ENCODING_TYPE_OFFSET: usize = 1;

    assert_eq!(bytes[VARIANT_OFFSET], 0, "BlobMetadata::V1 is variant 0");
    assert_eq!(
        bytes[ENCODING_TYPE_OFFSET], 1,
        "RS2 encoding type is 1 — this is the byte the network rejected when it \
         was 0"
    );

    bytes[ENCODING_TYPE_OFFSET] = 0;
    let result = bcs::from_bytes::<BlobMetadata>(&bytes);
    assert!(
        result.is_err(),
        "encoding type 0 is the deprecated RedStuffRaptorQ and must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Decode gates — upstream-generated vectors
// ---------------------------------------------------------------------------

/// The blob gate A pins, byte for byte. Reused so the decode vectors below
/// describe the same encode gate A already anchors to an upstream test.
const VECTOR_BLOB: &[u8] = b"walrus blob id v1 regression test";

/// The shard count gate A pins.
const VECTOR_N_SHARDS: u16 = 10;

/// BCS of the OUTER `BlobMetadataWithId`, dumped from upstream at `14641cc0`.
///
/// This is the shape a storage node returns from a metadata GET, and therefore
/// the shape `redstuff_verify_metadata` accepts. It is NOT what
/// `RedstuffEncodeResult.metadata_bcs` emits — that is the INNER `BlobMetadata`,
/// which gate E proves is exactly this value with its leading 32-byte blob ID
/// removed.
const UPSTREAM_METADATA_WITH_ID: &str = "45c53cd8cc1ff82164bf52da23fdaa72900dc29194b86dd33309d5cd9c43da46000121000000000000000a01e72fef473a7821fd33d556b2c2cee51481e6198fbccc8904232ae517c25b507f013e97b1aacf9199e3d46a777da0c6026de6aede8aeb509e53a5df0b01a5beacd20155d5a58919276c90651042b0ec1d0d35bb1b2a929f2fa95e085989425242ee0901c810d14be2ecb4f867ef6fb570e3d1510d4f95134e4954508f729d650756fc9c01eeab527996463b162b6f2a28f21f93ac8a1a7ef6c20b0a80acc7ad31da1a2a1301a28c1e22da86bd81a26deb87e57b0bb7227ed15cdb2dc147966bc74f17fe455d01db58f368d9bc3234adaa423ddfadfc96debcfa47a72d873ecb8f5207c1b6938c019ef0a0181da2557942b107108474b195740449a1d5c46b8e0fd553754b1a4979014b86fc43d2e66fd8b19608c610f60ec3966ea6e586ad2ec2db597867df87dc27013c9195499393d232a46dce52406e3b3ab73175280daf5d9dd3d6457de88162d501c5b7e89da87885932d161b77ca23a1958c4cdb293accbc74ab41e181896468af019f20dcfe4fbbc9d5598960d88001c90b0233a73114de7bd8282be45ef9346c9a01a43f04e88e194a04165ec3f1296ade9231306cbff75e2836f8aae574e93b44ec01d239ba8556f4092d9367863e3c5b92b224f1013071b777ad714e1f5cbe23d4ab018a77eefce6034ba2b0a4b42a794b4d079172414988c1a8c3caa66d16050c1249014a4047f09ff8984e745f5878aa2d2ffe16f35e1b2c3d86c012c21acb99c5cc890172393788b3b8ff581ac6b69c49c317620fb8c20b1b0b2b878a2b076d3cf587c6018357bc92f074ffcaece752250433589806684212ba5697cfb2f37a8bd993bde70125dfa6027b65405b4173b0a6e6c1cbe2178a4418bdf0175dc2c37dbd75df196d018d78c10ebb5bccc04da95cfab8b0abdfd332f24c265a1a4d953355c99cecde7d";

/// BCS of each primary sliver, indexed by `SliverIndex`, dumped from upstream.
///
/// Indices 0–3 hold the four SOURCE rows of the message matrix and are legible
/// as text; 4–9 are repair symbols. `n_shards = 10` gives `f = 3`, so the
/// primary axis has `n - 2f = 4` source symbols.
const UPSTREAM_PRIMARY_SLIVERS: [&str; 10] = [
    "0e77616c72757320626c6f6220696402000000",
    "0e2076312072656772657373696f6e02000100",
    "0e207465737400000000000000000002000200",
    "0e000000000000000000000000000002000300",
    "0ecdab9372da2a311fb51600f68aec02000400",
    "0e6837e01b271832230c237a0065eb02000500",
    "0e488caad2232cc90baa07c049298302000600",
    "0e9a73e19aad088d271a2eabf6c08e02000700",
    "0ef55f56e49f1d4c484143d270d8be02000800",
    "0ef5922d0de94cd01282141b50fbb802000900",
];

/// BCS of each secondary sliver, indexed by `SliverIndex`, dumped from upstream.
///
/// Indices 0–6 hold the seven SOURCE columns of the message matrix; 7–9 are
/// repair symbols. The secondary axis has `n - f = 7` source symbols.
///
/// Note the index relationship these encode: secondary sliver `j` belongs to
/// sliver PAIR `n_shards - 1 - j`. Gate I depends on that asymmetry.
const UPSTREAM_SECONDARY_SLIVERS: [&str; 10] = [
    "08776120762074000002000000",
    "086c7231206573000002000100",
    "08757372657200000002000200",
    "08206267720000000002000300",
    "086c6f65730000000002000400",
    "08622073690000000002000500",
    "0869646f6e0000000002000600",
    "0805f6374b8bdc000002000700",
    "081a1e172fb6d1000002000800",
    "08c2f80b0295ac000002000900",
];

/// Decodes a hex string from the upstream vector dump.
fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "hex must be byte-aligned");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn vector_shards() -> NonZeroU16 {
    NonZeroU16::new(VECTOR_N_SHARDS).expect("nonzero")
}

fn primary_sliver(index: usize) -> SliverData<Primary> {
    bcs::from_bytes(&unhex(UPSTREAM_PRIMARY_SLIVERS[index])).expect("upstream primary sliver")
}

fn secondary_sliver(index: usize) -> SliverData<Secondary> {
    bcs::from_bytes(&unhex(UPSTREAM_SECONDARY_SLIVERS[index])).expect("upstream secondary sliver")
}

/// Parses and verifies the upstream metadata, returning the verified handle.
fn upstream_verified_metadata() -> VerifiedBlobMetadataWithId {
    let config = EncodingConfig::new(vector_shards());
    let unverified: UnverifiedBlobMetadataWithId =
        bcs::from_bytes(&unhex(UPSTREAM_METADATA_WITH_ID)).expect("upstream metadata parses");
    unverified
        .verify(&config)
        .expect("upstream metadata verifies")
}

/// Gate D — the sliver BCS wire shape must match upstream on BOTH axes.
///
/// This is the gate that the blob ID cannot provide. `blob_id` commits to the
/// sliver HASHES, not to how a sliver is serialised, so gates A and F–H all pass
/// even if this crate's `SliverData` layout has drifted from upstream's — encode
/// and decode would simply agree with each other and disagree with the network.
/// That is the gate C failure class exactly: invisible locally, fatal on the
/// wire. It matters more for decode than for encode, because decode consumes
/// bytes produced by somebody else's node.
///
/// Primary sliver 0, byte by byte:
/// ```text
///   0e                                ULEB128 length of symbols.data = 14
///   77616c72757320626c6f622069 64      "walrus blob id"
///   0200                              symbols.symbol_size = 2, u16 LE
///   0000                              index = SliverIndex(0), u16 LE
/// ```
/// The payload is legible because primary sliver 0 is the first ROW of the
/// message matrix: 7 symbols of 2 bytes.
#[test]
fn gate_d_sliver_bcs_wire_shape_matches_upstream() {
    let raw_primary = unhex(UPSTREAM_PRIMARY_SLIVERS[0]);
    let primary: SliverData<Primary> =
        bcs::from_bytes(&raw_primary).expect("upstream primary sliver parses");
    assert_eq!(primary.symbols.data(), b"walrus blob id");
    assert_eq!(primary.symbols.symbol_size().get(), 2);
    assert_eq!(primary.index.0, 0);
    assert_eq!(
        bcs::to_bytes(&primary).expect("re-serialise"),
        raw_primary,
        "primary sliver serialisation diverged from upstream — storage nodes \
         would reject or misread every sliver"
    );

    // Secondary sliver 0 is the first COLUMN: 4 symbols of 2 bytes, holding
    // blob bytes 0-1, 14-15, 28-29 and the zero pad.
    let raw_secondary = unhex(UPSTREAM_SECONDARY_SLIVERS[0]);
    let secondary: SliverData<Secondary> =
        bcs::from_bytes(&raw_secondary).expect("upstream secondary sliver parses");
    assert_eq!(secondary.symbols.data(), b"wa v t\0\0");
    assert_eq!(secondary.symbols.symbol_size().get(), 2);
    assert_eq!(secondary.index.0, 0);
    assert_eq!(
        bcs::to_bytes(&secondary).expect("re-serialise"),
        raw_secondary,
        "secondary sliver serialisation diverged from upstream"
    );
}

/// Gate E — the metadata GET and PUT shapes, and their exact relationship.
///
/// `redstuff_verify_metadata` takes the OUTER `...WithId` (what a node returns
/// from a metadata GET); `RedstuffEncodeResult.metadata_bcs` emits the INNER
/// `BlobMetadata` (what a metadata PUT expects). Confusing the two is a
/// documented footgun on both functions, and this pins the difference to a
/// single upstream-generated value rather than to prose.
#[test]
fn gate_e_metadata_wire_shapes_match_upstream() {
    let with_id = unhex(UPSTREAM_METADATA_WITH_ID);

    let config = ReedSolomonEncodingConfig::new(vector_shards());
    let encoder = config.get_blob_encoder(VECTOR_BLOB).expect("blob encoder");
    let (_sliver_pairs, metadata) = encoder.encode_with_metadata();

    assert_eq!(
        bcs::to_bytes(&metadata).expect("with-id serialises"),
        with_id,
        "our ...WithId serialisation diverged from upstream"
    );
    assert_eq!(
        &with_id[..32],
        &metadata.blob_id().0[..],
        "the ...WithId wrapper must begin with the raw 32-byte blob ID"
    );
    assert_eq!(
        &with_id[32..],
        &bcs::to_bytes(metadata.metadata()).expect("inner serialises")[..],
        "the inner BlobMetadata must be the ...WithId with its 32-byte blob ID \
         prefix removed — this is the GET/PUT asymmetry callers trip over"
    );

    let verified = upstream_verified_metadata();
    assert_eq!(verified.blob_id().0, metadata.blob_id().0);
}

/// Gate F — decode the primary axis from upstream REPAIR slivers.
///
/// Deliberately uses slivers 4-7, which are all repair symbols. Slivers 0-3 are
/// the source rows of the message matrix, so decoding from those is a memcpy
/// and exercises no Reed-Solomon reconstruction whatsoever — it would pass
/// against a decoder that did nothing but concatenate.
#[test]
fn gate_f_primary_decode_from_upstream_repair_slivers() {
    let slivers: Vec<SliverData<Primary>> = (4..8).map(primary_sliver).collect();
    let config = ReedSolomonEncodingConfig::new(vector_shards());
    let decoder = config
        .get_blob_decoder::<Primary>(VECTOR_BLOB.len() as u64)
        .expect("primary blob decoder");

    assert_eq!(
        decoder.decode(slivers).expect("primary decode succeeds"),
        VECTOR_BLOB,
        "primary decode did not reproduce the blob upstream encoded"
    );
}

/// Gate G — decode the secondary axis. NOT redundant with gate F.
///
/// On the primary axis a sliver's axis-local index and its pair index are the
/// same number by construction, so an error in the axis-local/pair index
/// conversion is invisible there. On the secondary axis they differ — secondary
/// sliver `j` belongs to pair `n_shards - 1 - j` — so this is the only gate that
/// can catch that class of bug. See the CAUTION block on the `SliverIndex`
/// `From` impls in `vendored/core.rs`.
///
/// Uses slivers 3-9: four source columns and three repair, forcing actual
/// reconstruction of columns 0, 1 and 2.
#[test]
fn gate_g_secondary_decode_from_upstream_slivers() {
    let slivers: Vec<SliverData<Secondary>> = (3..10).map(secondary_sliver).collect();
    let config = ReedSolomonEncodingConfig::new(vector_shards());
    let decoder = config
        .get_blob_decoder::<Secondary>(VECTOR_BLOB.len() as u64)
        .expect("secondary blob decoder");

    assert_eq!(
        decoder.decode(slivers).expect("secondary decode succeeds"),
        VECTOR_BLOB,
        "secondary decode did not reproduce the blob upstream encoded"
    );
}

/// Gate H — one sliver below the threshold must fail, not return wrong bytes.
///
/// The thresholds are asymmetric: `n - 2f = 4` primary slivers, `n - f = 7`
/// secondary. A decoder that silently produced a short or garbage blob when
/// starved would be far worse than one that errors, because the caller's next
/// step is to trust those bytes.
#[test]
fn gate_h_decode_below_threshold_fails() {
    let config = ReedSolomonEncodingConfig::new(vector_shards());

    let three_primary: Vec<SliverData<Primary>> = (4..7).map(primary_sliver).collect();
    let decoder = config
        .get_blob_decoder::<Primary>(VECTOR_BLOB.len() as u64)
        .expect("primary blob decoder");
    assert_eq!(
        decoder.decode(three_primary),
        Err(DecodeError::DecodingUnsuccessful),
        "3 primary slivers is one below the n-2f threshold and must fail"
    );

    let six_secondary: Vec<SliverData<Secondary>> = (4..10).map(secondary_sliver).collect();
    let decoder = config
        .get_blob_decoder::<Secondary>(VECTOR_BLOB.len() as u64)
        .expect("secondary blob decoder");
    assert_eq!(
        decoder.decode(six_secondary),
        Err(DecodeError::DecodingUnsuccessful),
        "6 secondary slivers is one below the n-f threshold and must fail"
    );
}

/// Gate I — sliver verification against upstream metadata, on both axes.
///
/// The secondary half is the load-bearing one. `check_hash` looks the sliver's
/// hash up by PAIR index, converting from the axis-local index; on the primary
/// axis that conversion is the identity, so only the secondary case proves the
/// conversion is real. A crate that returned the axis-local index unchanged
/// would pass every other gate in this file and then reject honest secondary
/// slivers from every storage node.
#[test]
fn gate_i_sliver_verification_matches_upstream_metadata() {
    let config = EncodingConfig::new(vector_shards());
    let verified = upstream_verified_metadata();
    let metadata = verified.metadata();

    primary_sliver(0)
        .verify(&config, metadata)
        .expect("upstream primary sliver verifies against upstream metadata");
    secondary_sliver(0)
        .verify(&config, metadata)
        .expect("upstream secondary sliver verifies against upstream metadata");

    // Flip the first payload byte (index 0 is the ULEB128 length prefix).
    let mut corrupted_bytes = unhex(UPSTREAM_PRIMARY_SLIVERS[0]);
    corrupted_bytes[1] ^= 0xff;
    let corrupted: SliverData<Primary> =
        bcs::from_bytes(&corrupted_bytes).expect("corrupted sliver still parses");
    assert_eq!(
        corrupted.verify(&config, metadata),
        Err(SliverVerificationError::MerkleRootMismatch),
        "a single flipped byte must be caught as a Merkle root mismatch — this \
         is the only signal that a storage node served bad data"
    );
}
