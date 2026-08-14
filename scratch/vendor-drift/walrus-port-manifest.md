# Walrus Port Manifest — Backlog #7 / Issue #15

Source: local clone `~/mysten_repos/walrus`, pinned commit `14641cc0edcc727825d07aa19df2eef8046a3c0d`. Paths below are relative to `crates/walrus-core/src/`. Apache-2.0.

**This file is the authoritative input to `.claude/commands/vendor-drift-check.md`.** Drift checks must diff these specific items, not whole files. Established 2026-08-14 (Phase 4 gap-resolution pass).

Entry point: `BlobEncoder::encode_with_metadata` — `encoding/blob_encoding.rs:266-368`, signature `pub fn encode_with_metadata(self) -> (Vec<SliverPair>, VerifiedBlobMetadataWithId)`. Takes `self` BY VALUE and does `drop(self.blob)` mid-function (`:302`).

---

## encoding/blob_encoding.rs

| Item | Lines | Vis |
|---|---|---|
| `enum OwnedOrBorrowedBlob<'a>` | 33-40 | pub |
| `OwnedOrBorrowedBlob::new` | 43-46 | pub |
| `OwnedOrBorrowedBlob::len` | 57-63 | pub |
| `OwnedOrBorrowedBlob::new_owned` | 72-75 | pub |
| `impl AsRef<[u8]> for OwnedOrBorrowedBlob` | 78-85 | pub |
| `struct BlobEncoderData` | 87-104 | private |
| `BlobEncoderData::get_encoder<E>` | 107-112 | private |
| `BlobEncoderData::symbol_usize` | 114-117 | pub |
| `BlobEncoderData::sliver_length<E>` | 119-121 | private |
| `BlobEncoderData::empty_sliver<E>` | 123-129 | private |
| `BlobEncoderData::empty_slivers<E>` | 131-134 | private |
| `BlobEncoderData::empty_slivers_range<E>` | 136-141 | private |
| `BlobEncoderData::compute_metadata_from_symbol_hashes` | 152-196 | pub |
| `BlobEncoderData::n_rows_usize` | 198-200 | private |
| `BlobEncoderData::n_columns_usize` | 202-204 | private |
| `BlobEncoderData::n_shards_usize` | 206-208 | private |
| `struct BlobEncoder<'a>` | 211-221 | pub |
| `BlobEncoder::new` | 224-264 | pub |
| `BlobEncoder::encode_with_metadata` | 266-368 | pub |
| `BlobEncoder::blob` | 488-491 | pub |
| `BlobEncoder::symbol_usize` | 495-498 | pub |
| `BlobEncoder::symbol_at` | 500-511 | private |
| `BlobEncoder::column_symbols` | 513-520 | private |
| `BlobEncoder::rows` | 522-525 | private |

## encoding/mapping.rs — REQUIRED (see Critical Finding below)

| Item | Lines | Vis |
|---|---|---|
| `enum SliverAssignmentError` | 12-22 | pub |
| `rotate_pairs` | 24-66 | pub |
| `rotate_pairs_unchecked` | 68-77 | pub |
| `is_rotation` | 79-86 | private |
| `SliverPairIndex::to_shard_index` | 89-98 | pub |
| `ShardIndex::to_pair_index` | 102-110 | pub |
| `rotation_offset` | 113-115 | private |
| `rotate_by_bytes` | 117-125 | private |
| `bytes_mod` | 127-134 | private |

**Expanded 2026-08-14 (Phase 5).** The original two-row list named only the public entry points. `rotate_pairs` cannot compile without the private helpers and the two index-conversion impls, so `mapping.rs` is now ported IN FULL apart from `#[cfg(test)] mod tests` (136-318). These are transitive dependencies, not scope additions.

`rotate_pairs` also requires `ShardIndex`, which the `lib.rs` list omitted. `index_type!(ShardIndex)` (`lib.rs:513-517`) is now ported — see the `lib.rs` table. Deliberately NOT ported: `ShardRange` (`lib.rs:519-522`), `ShardIndex::range` (`lib.rs:524-555`), `impl From<ShardIndex> for usize` (`lib.rs:557-561`) — unused by the encode path.

## encoding/common.rs

| Item | Lines | Vis |
|---|---|---|
| `trait EncodingAxis` | 10-25 | pub |
| `struct Primary` + `impl EncodingAxis` | 27-34 | pub |
| `struct Secondary` + `impl EncodingAxis` | 36-43 | pub |

`EncodingAxis::sliver_type()` (22-24) is a default method never called on the encode path — dropping it removes the only dependency on `SliverType` / `by_axis::Axis`.

## encoding/utils.rs

| Item | Lines | Vis |
|---|---|---|
| `compute_symbol_size` | 8-25 | pub |
| `compute_symbol_size_from_usize` | 27-39 | pub |
| `source_symbols_per_blob` | 41-50 | pub |

## encoding/symbols.rs

| Item | Lines | Vis |
|---|---|---|
| `struct Symbols` (`#[serde_as]`, `#[serde_as(as="Bytes")]` on `data`) | 39-49 | pub |
| `Symbols::new` | 52-64 | pub |
| `Symbols::truncate` | 66-72 | pub |
| `Symbols::zeros` | 74-80 | pub |
| `Symbols::with_capacity` | 82-96 | pub |
| `Symbols::set_min_capacity` | 104-109 | pub |
| `Symbols::to_symbols` | 173-177 | pub |
| `Symbols::to_symbols_mut` | 179-184 | pub |
| `Symbols::extend` | 201-214 | pub |
| `Symbols::symbol_size` | 216-220 | pub |
| `Symbols::symbol_usize` | 222-226 | pub |
| `Symbols::data` | 228-232 | pub |
| `Symbols::data_mut` | 234-238 | pub |
| `Symbols::symbol_range` | 240-244 | pub |
| `impl Index<usize> for Symbols` | 253-259 | pub |
| `impl IndexMut<usize> for Symbols` | 261-266 | pub |

NOT needed: `reserve` (98-102), `from_slice` (111-119), `len` (121-125), `is_empty` (127-131), `get` (133-144), `get_mut` (146-156), `decoding_symbol_at` (158-171), `to_decoding_symbols` (186-199), `into_vec` (246-250), `Index/IndexMut<Range>` (268-281), `AsRef/AsMut<[u8]>` (283-293).

## encoding/slivers.rs

| Item | Lines | Vis |
|---|---|---|
| `type PrimarySliver` | 40-41 | pub |
| `type SecondarySliver` | 43-44 | pub |
| `struct SliverData<T: EncodingAxis>` | 46-56 | pub |
| `SliverData::new_empty` | 73-82 | pub |
| `SliverData::copy_symbol_to` | 84-94 | pub |
| `struct SliverPair` | 427-434 | pub |
| `SliverPair::index` | 437-442 | pub |

`SliverData::new` (59-70) not used by `encode_with_metadata`.

**Correction 2026-08-14 (Phase 5).** `SliverPair::index` was originally on the deliberate-exclusion list, but `mapping::rotate_pairs` — a REQUIRED item — calls it at `mapping.rs:57`, `mapping.rs:59`, and via `is_rotation` at `mapping.rs:84`. The exclusion contradicted the requirement; the required item wins. Now ported, and removed from the exclusion list below.

## encoding/basic_encoding.rs

| Item | Lines | Vis |
|---|---|---|
| `struct ReedSolomonEncoder` | 71-78 | pub |
| `impl Debug for ReedSolomonEncoder` | 80-88 | pub |
| `const ASSOCIATED_ENCODING_TYPE` | 91 | private |
| `ReedSolomonEncoder::new` | 93-142 | pub |
| `check_parameters_and_compute_symbol_size` | 144-162 | pub(super) |
| `encode_all_ref` | 176-186 | pub |
| `encode_all` | 188-211 | pub |
| `encode_all_repair_symbols_inner` | 228-248 | private |
| `take_or_create_encoded_symbols` | 250-259 | private |
| `set_and_return_encoded_symbols` | 261-266 | private |
| `check_data_length` | 295-303 | private |
| `encode` | 305-319 | pub(crate) |
| `reset` | 321-329 | private |
| `reed_solomon_original_count` | 331-333 | private |
| `reed_solomon_recovery_count` | 335-337 | private |
| `reed_solomon_shard_bytes` | 339-341 | private |

`trait Decoder` (30-69) is NOT required. `ReedSolomonDecoder` (347-431) excluded.

## encoding/config.rs

| Item | Lines | Vis |
|---|---|---|
| `const MAX_SOURCE_SYMBOLS` | 37-39 | pub |
| `trait EncodingFactory` — SUBSET ONLY | 41-336 | pub |
| — `encoding_type` (required) | 45 | |
| — `n_primary_source_symbols` (required) | 175 | |
| — `n_secondary_source_symbols` (required) | 178 | |
| — `n_shards` (required) | 181 | |
| — `n_source_symbols<E>` (default) | 183-191 | |
| — `n_shards_as_usize` (default) | 212-216 | |
| — `source_symbols_per_blob` (default) | 232-239 | |
| `enum EncodingConfigEnum` | 408-414 | pub |
| `struct ReedSolomonEncodingConfig` | 416-432 | pub |
| `const ENCODING_TYPE` | 435 | private |
| `ReedSolomonEncodingConfig::new` | 437-460 | pub |
| `new_from_nonzero_parameters` | 462-504 | pub(crate) |
| `get_encoder<E>` | 525-534 | pub(crate) |
| `get_blob_encoder` | 543-550 | pub |
| `get_blob_encoder_owned` | 552-559 | pub |
| `impl EncodingFactory for ReedSolomonEncodingConfig` | 570-708 | pub |
| `fn source_symbols_for_n_shards` | 710-725 | pub |
| `struct EncodingConfig` + `new` + `get_for_type` + `n_shards` | 352-406 | pub — OPTIONAL |

WARNING: `EncodingFactory::encode_with_metadata` (config.rs:591-596) is a DIFFERENT function from `BlobEncoder::encode_with_metadata`. Name collision — guard against confusing them in the port.

`EncodingFactory` mixes encode and decode in one trait. Porting verbatim drags in `Decoder`, `DecodingSymbol`, `ByAxis`, `ConsistencyCheckType`, `BlobDecoder`, `SliverData::verify`. Port only the 7-member subset above, OR drop the trait and use inherent impls on `ReedSolomonEncodingConfig` (only one variant exists, so `EncodingConfigEnum` + `enum_dispatch` can collapse to a plain struct — `BlobEncoderData::get_encoder` at :107-113 already destructures irrefutably).

## encoding/errors.rs

| Item | Lines | Vis |
|---|---|---|
| `struct DataTooLargeError` | 10-13 | pub |
| `enum InvalidDataSizeError` | 15-24 | pub |
| `impl From<DataTooLargeError> for InvalidDataSizeError` | 26-30 | pub |
| `enum EncodeError` | 32-44 | pub |
| `struct WrongSymbolSizeError` | 120-123 | pub |

## merkle.rs

| Item | Lines | Vis |
|---|---|---|
| `const DIGEST_LEN` | 15-16 | pub |
| `const LEAF_PREFIX` = `[0]` | 18 | private |
| `const INNER_PREFIX` = `[1]` | 19 | private |
| `const EMPTY_NODE` = `[0u8;32]` | 20 | private |
| `enum Node` | 36-43 | pub |
| `Node::bytes` | 46-52 | pub |
| `impl From<Digest<32>> for Node` | 55-59 | pub |
| `impl AsRef<[u8]> for Node` | 67-74 | pub |
| `struct MerkleTree<T = Blake2b256>` | 188-200 | pub |
| `impl Debug for MerkleTree` | 202-209 | pub |
| `MerkleTree::build` | 215-223 | pub |
| `MerkleTree::build_from_leaf_hashes` | 225-266 | pub |
| `MerkleTree::root` | 273-276 | pub |
| `fn leaf_hash<T>` | 312-321 | pub(crate) |
| `fn inner_hash<T>` | 323-332 | private |
| `fn n_nodes` | 334-343 | private |

NOT needed: `MerkleProofError` (22-34), `From<[u8;32]> for Node` (61-65), `trait MerkleAuth` (76-102), `MerkleProof` (104-186), `verify_root` (268-271), `get_proof` (278-309), `path_length` (345-351).

## metadata.rs

| Item | Lines | Vis |
|---|---|---|
| `type VerifiedBlobMetadataWithId` | 317-323 | pub |
| `struct BlobMetadataWithId<const V: bool>` | 330-340 | pub |
| `new_verified_from_metadata` | 348-361 | pub |
| `new_verified_unchecked` | 363-370 | pub |
| `blob_id` | 372-375 | pub |
| `metadata` | 377-380 | pub |
| `trait BlobMetadataApi` — members `compute_root_hash` (471), `encoding_type` (483), `unencoded_length` (486), `hashes` (489) | 461-491 | pub |
| `enum BlobMetadata` | 493-499 | pub |
| `BlobMetadata::new` | 502-514 | pub |
| `BlobMetadata::encoding_type` | 516-521 | pub |
| `struct BlobMetadataV1` | 534-543 | pub |
| `impl Debug for BlobMetadataV1` | 545-553 | pub |
| `BlobMetadataV1::compute_root_hash` | 570-578 | pub |
| `BlobMetadataV1::encoding_type` / `unencoded_length` / `hashes` | 604-614 | pub |
| `struct SliverPairMetadata` | 617-624 | pub |
| `SliverPairMetadata::pair_leaf_input<T>` | 635-643 | pub |

NOT needed: `get_sliver_hash` (464-469/556-568), `symbol_size` (474-478/580-588), `encoded_size` (480-481/590-602), `new_empty` (627-633), `hash<T>` (645-652), `BlobMetadataWithId::new` (343-346), `into_unverified` (384-390), `is_encoding_config_applicable` (392-404), `n_shards` (406-416), `UnverifiedBlobMetadataWithId::verify` (419-453), all Quilt types (63-315).

## lib.rs

| Item | Lines | Vis |
|---|---|---|
| `pub type Epoch` | 81-82 | pub |
| `struct BlobId` | 107-116 | pub |
| `BlobId::LENGTH` | 119-120 | pub |
| `BlobId::from_metadata` | 128-132 | pub |
| `BlobId::from_sliver_pair_metadata` | 134-145 | pub |
| `BlobId::new_with_hash_function<T>` | 159-165 | private |
| `impl AsRef<[u8]> for BlobId` | 179-183 | pub |
| `impl Display for BlobId` | 185-189 | pub |
| `impl Debug for BlobId` | 191-195 | pub |
| `struct SuiObjectId` | 326-333 | pub |
| `macro_rules! index_type` | 384-422 | private |
| `SliverIndex` | 426-431 | pub |
| `SliverPairIndex` | 433-441 | pub |
| `SliverPairIndex::to_sliver_index` | 474-491 | pub |
| `index_type!(ShardIndex)` | 513-517 | pub |
| `enum EncodingType` | 775-784 | pub |
| `impl From<EncodingType> for u8` | 809-814 | pub |
| `EncodingType::required_alignment` | 841-847 | pub |
| `macro_rules! ensure` | 906-957 | exported |

Blob ID derivation: `Blake2b256( [encoding_type as u8] || unencoded_length.to_le_bytes() || merkle_root.bytes() )`. `EncodingType::RS2 = 1`. `Display` is base64url NO PADDING.

## utils.rs

| Item | Lines | Vis |
|---|---|---|
| `macro_rules! wrapped_uint` | 12-77 | exported |
| `fn data_prefix_string` | 79-111 | pub |

`wrapped_uint!` injects `#[serde(transparent)]` (utils.rs:26) — this is why the intent bytes serialize flat.

## bft.rs

| Item | Lines | Vis |
|---|---|---|
| `fn max_n_faulty` | 8-14 | pub |
| `fn min_n_correct` | 16-25 | pub |

## messages.rs / messages/storage_confirmation.rs / messages/certificate.rs

| Item | File:Lines | Vis |
|---|---|---|
| `struct ProtocolMessage<T>` (`intent`, `epoch: u32`, `message_contents: T`) | messages.rs:46-53 | pub |
| `struct Intent` + `Intent::storage` | messages.rs:220-239 | pub |
| `IntentType` / `IntentVersion` / `IntentAppId` constants | messages.rs:182-218 | pub |
| `enum BlobPersistenceType` | storage_confirmation.rs:23-35 | pub |
| `struct StorageConfirmationBody` | storage_confirmation.rs:37-45 | pub |
| `struct Confirmation` | storage_confirmation.rs:47-51 | pub |
| `struct InvalidIntent` | messages.rs:146-152 | pub |
| `impl Confirmation` (`INTENT` const, `new`) | storage_confirmation.rs:53-65 | pub |
| `impl TryFrom<ProtocolMessage<StorageConfirmationBody>> for Confirmation` | storage_confirmation.rs:67-81 | pub |
| `BLS12381AggregateSignature::aggregate` usage | messages/certificate.rs:75 | — |

`BlobPersistenceType`: `Permanent` → `0x00` (1 byte); `Deletable { object_id: SuiObjectId }` → `0x01` + 32 raw bytes. No serde attributes — default externally-tagged BCS. `SuiObjectId` is walrus-core's own type (`lib.rs:326-338`), `[u8; 32]`, `#[repr(transparent)]`, no ULEB prefix.

Exact signed-byte layout (asserted upstream at storage_confirmation.rs:117-171):

| offset | len | content |
|---|---|---|
| 0 | 1 | `IntentType::BLOB_CERT_MSG` = `0x01` |
| 1 | 1 | `IntentVersion::DEFAULT` = `0x00` |
| 2 | 1 | `IntentAppId::STORAGE` = `0x03` |
| 3 | 4 | `epoch: u32` little-endian |
| 7 | 32 | `blob_id` raw |
| 39 | 1 | persistence variant index |
| 40 | 32 | `object_id` raw — ONLY if `Deletable` |

Total 40 bytes (permanent) / 72 bytes (deletable).

**Correction 2026-08-14 (Phase 5).** The original table listed `struct Confirmation` but not `impl Confirmation` (which holds the `INTENT` const and `new`), nor the `TryFrom` impl, nor `InvalidIntent`. `Confirmation` carries `#[serde(try_from = "ProtocolMessage<StorageConfirmationBody>")]`, so the derived `Deserialize` does not compile without the `TryFrom` impl, which in turn returns `InvalidIntent`. Same class of omission as `SliverPair::index`: a required item's dependencies were not listed. All three are now vendored. `messages/certificate.rs` remains a usage note only — the aggregate call sits inside `ProtocolMessageCertificate`, which is not vendored; BLS aggregation lives in this crate's own `walrus::bls`.

---

## Deliberately excluded (decode / recovery / legacy / quilt)

- **blob_encoding.rs:** `OwnedOrBorrowedBlob::into_owned` (48-55), `is_empty` (65-68); `BlobEncoderData::empty_sliver_pairs` (143-150); `encode_with_metadata_legacy` (370-403, `#[deprecated]`); `compute_metadata` (405-486); `rows_all` (527-539); `get_expanded_matrix` (541-547); `systematic_primary_sliver` (549-559); `default_consistency_check` (561-612); `ExpandedMessageMatrix` (615-799); `BlobDecoder` (801-998).
- **basic_encoding.rs:** `trait Decoder` (29-67); `ReedSolomonDecoder` (344-430); `encode_all_repair_symbols` (213-226); `get_symbol` (268-293); `BLOB_TYPE_ATTRIBUTE_KEY` (23-24); `QUILT_TYPE_VALUE` (26-27).
- **symbols.rs:** `DecodingSymbol` (295-358), `EitherDecodingSymbol` (360-402), `GeneralRecoverySymbol` (407-530), `RecoverySymbol`/`Primary`/`Secondary` (573-664), `RecoverySymbolPair` (666-674).
- **slivers.rs:** `verify` (96-119), `check_hash` (121-144), `has_correct_length` (146-152), `expected_length` (154-159), `recovery_symbols` (161-178), `recovery_symbol_for_sliver` (180-211), `decoding_symbol_for_sliver` (213-238), `recover_sliver_without_verification` (240-265), `recover_sliver_from_decoding_symbols` (267-295), `try_recover_sliver_from_decoding_symbols` (297-326), `recover_sliver_or_generate_inconsistency_proof` (328-379), `get_merkle_root` (381-392), `len`/`is_empty` (394-402), `check_index` (404-412), `Display` (415-425); `SliverPair::new_empty` (444-463), `recovery_symbol_pair_for_sliver` (465-490), `pair_leaf_input` (492-509).
- **config.rs:** `encode_all_symbols` (52-53), `encode_all_repair_symbols` (55-59), `encode_symbol` (61-68), `decode_from_decoding_symbols` (70-82), `compute_metadata` (101-105), `compute_blob_id` (107-110), `decode` (112-125), `decode_and_verify` (127-156), `strict_consistency_check` (158-172), `n_systematic_slivers` (193-198), `n_symbols_for_recovery` (200-204), `n_slivers_for_reconstruction` (206-210), `max_data_size` (218-222), `max_blob_size` (224-230), `symbol_size_for_blob*` (241-272), `sliver_size_for_blob` (292-303), `encoded_blob_length*` (305-319), `metadata_length` (321-327), `max_sliver_size` (329-335), `max_symbol_size` (47-50); `enum RequiredCount` (346-350); `get_decoder` (536-541); `get_blob_decoder` (561-567).
- **Whole files:** `encoding/quilt_encoding.rs`, `inconsistency.rs`, `by_axis.rs`, `keys.rs`, `test_utils.rs`, `messages/certificate.rs`.
- **encoding/errors.rs:** `DecodeError` (46-66), `DecodeError::from` (69-71), `RecoverySymbolError` (74-83), `RecoverySymbolError::from` (86-88), `SliverRecoveryError` (91-100), `SliverRecoveryOrVerificationError` (102-112), `SliverRecoveryOrVerificationError::from` (115-117), `WrongSliverVariantError` (125-129), `SliverVerificationError` (131-149), `SymbolVerificationError` (151-170), `QuiltError` (172-242).
- **encoding/common.rs:** `ConsistencyCheckType` (45-56), `ConsistencyCheckType::fmt` (59-65).
- **encoding/slivers.rs:** `SliverData::new` (59-71).
- **encoding/basic_encoding.rs:** `ReedSolomonEncoder::symbol_size` (164-168), `ReedSolomonEncoder::n_source_symbols` (170-174).
- **encoding/symbols.rs:** `Symbols::reserve` (98-102), `Symbols::decoding_symbol_at` (158-171), `Symbols::to_decoding_symbols` (186-199), `Symbols::into_vec` (246-250), `DecodingSymbol::from` (533-540), `DecodingSymbol::from` (544-551), `EitherRecoverySymbol::from` (555-570).
- **encoding/config.rs:** `ReedSolomonEncodingConfig::new_for_test` (506-523), `metadata_length_for_n_shards` (727-740), `max_sliver_size_for_n_secondary` (742-749), `max_sliver_size_for_n_shards` (751-758), `max_blob_size_for_n_shards` (760-773), `source_symbols_per_blob_for_n_shards` (775-781), `encoded_blob_length_for_n_shards` (783-799), `encoded_slivers_length_for_n_shards` (801-826).
- **metadata.rs:** `VerificationError` (43-61), `QuiltPatchV1` (63-78), `UnverifiedBlobMetadataWithId` (325-328), `VerifiedBlobMetadataWithId::is_encoding_config_applicable` (392-404), `VerifiedBlobMetadataWithId::n_shards` (406-416), `BlobMetadataWithId::as_ref` (456-458), `BlobMetadata::mut_inner` (523-531), `BlobMetadataV1::get_sliver_hash` (556-568), `BlobMetadataV1::symbol_size` (580-588), `BlobMetadataV1::encoded_size` (590-602).
- **messages.rs:** `SignedMessage` (67-84), `SignedMessage::new_from_encoded` (87-94), `SignedMessage::verify_signature_and_get_message` (98-111), `SignedMessage::verify_signature_and_contents` (113-143), `MessageVerificationError` (154-177).
- **merkle.rs:** `path_length` (345-351).
- **lib.rs:** `PublicKey` (71-72), `NetworkPublicKey` (73-74), `Signature` (75-76), `Certificate` (77-78), `DefaultHashFunction` (79-80), `EpochCount` (83-84), `SUPPORTED_AND_DEFAULT_ENCODING` (86-88), `SUPPORTED_ENCODING_TYPES` (90-91), `DEFAULT_ENCODING` (93-94), `EpochSchema` (98-100), `BlobId::ZERO` (122-123), `BlobId::MAX` (125-126), `BlobId::first_two_bytes` (147-157), `QuiltPatchId` (197-208), `QuiltPatchId::new` (211-217), `QuiltPatchId::to_bytes` (219-225), `QuiltPatchId::from_bytes` (227-235), `QuiltPatchId::zero` (237-243), `QuiltPatchId::version_enum` (245-253), `QuiltPatchId::fmt` (257-259), `QuiltPatchId::fmt` (263-269), `QuiltPatchId::Err` (273-273), `QuiltPatchId::from_str` (275-294), `BlobIdParseError` (297-300), `BlobId::Error` (303-303), `BlobId::try_from` (305-308), `BlobId::Err` (312-312), `BlobId::from_str` (314-321), `SuiObjectId::LENGTH` (336-337), `SuiObjectId::from` (342-344), `SuiObjectId::from` (349-351), `ObjectID::from` (356-358), `ObjectID::from` (363-365), `SuiObjectIdParseError` (368-371), `SuiObjectId::Error` (374-374), `SuiObjectId::try_from` (376-379), `SliverPairIndex::from` (442-444), `SliverIndex::from` (448-450), `SliverIndex::partial_cmp` (454-456), `SliverIndex::eq` (460-462), `SliverIndex::Err` (466-466), `SliverIndex::from_str` (468-470), `SliverIndex::to_pair_index` (495-510), `ShardRange` (519-522), `ShardIndex::range` (525-554), `usize::from` (558-560), `Sliver` (565-568), `Sliver::hash` (571-575), `Sliver::len` (577-580), `Sliver::is_empty` (582-585), `Sliver::verify` (587-597), `Sliver::sliver_index` (599-602), `Sliver::to_raw` (604-611), `DecodingSymbolType` (617-618), `SliverType` (620-621), `SymbolId` (625-630), `SymbolId::new` (633-636), `SymbolId::primary_sliver_index` (638-641), `SymbolId::secondary_sliver_index` (643-646), `SymbolId::sliver_index` (648-657), `SymbolId::fmt` (661-663), `SymbolId::schema` (668-683), `SymbolId::name` (688-690), `ParseSymbolIdError` (693-698), `SymbolId::Err` (701-701), `SymbolId::from_str` (703-709), `SymbolId::serialize` (713-722), `SymbolId::deserialize` (726-736), `RecoverySymbol` (739-742), `InvalidEncodingType` (753-756), `EncodingTypeForSerde` (768-773), `EncodingType::Error` (788-788), `EncodingType::try_from` (790-796), `EncodingTypeForSerde::from` (801-806), `EncodingType::Error` (817-817), `EncodingType::try_from` (819-825), `EncodingType::Err` (829-829), `EncodingType::from_str` (831-837), `EncodingType::max_symbol_size` (849-855), `EncodingType::is_supported` (857-861), `EncodingType::fmt` (865-870), `InconsistencyProof` (875-881), `InconsistencyProof::verify` (884-894), `SliverId` (959-960), `SliverId::index` (963-966), `SliverId::pair_index` (968-974).
- **messages/storage_confirmation.rs:** `StorageConfirmation` (13-21), `Confirmation::as_ref` (84-86), `SignedStorageConfirmation` (89-90), `SignedStorageConfirmation::verify` (93-106).

---

## CRITICAL FINDING — SliverPairIndex is NOT shard index

Phase 1 research incorrectly reported that `Vec<SliverPair>` comes back shard-indexed. It does not.

Position `i` in the returned Vec is `SliverPairIndex(i)`. Within a pair the axes are correct — verified at `blob_encoding.rs:355-359`: primary slivers ascending by `SliverIndex`, secondary `.rev()`'d so pair `i` gets secondary `SliverIndex(n_shards-1-i)`, matching `SliverPairIndex::to_sliver_index::<Secondary>` (`lib.rs:485-491`).

But mapping PAIRS to SHARDS requires a blob-ID-dependent rotation: `rotate_pairs` (`encoding/mapping.rs:43-67`) interprets the blob ID as a big-endian unsigned integer and moves the last `blob_id % n_pairs` elements to the front (doc at `mapping.rs:29-33`).

Because the rotation needs the blob ID, it can only run AFTER encoding. Required order in the FFI layer: encode → metadata → blob_id → `rotate_pairs` → shard-indexed result.

Shipping without this would have sent every sliver to the wrong storage node with no local error — surfacing only as unexplained certification failures.

---

## Golden vectors available upstream

Exactly ONE genuine golden vector exists:

- `encoding/blob_encoding.rs:1227-1244`, `test_v1_blob_id_stability()` — blob `b"walrus blob id v1 regression test"` (33 bytes), `n_shards = 10` (primary 4, secondary 7), expected blob ID `RcU82Mwf-CFkv1LaI_2qcpANwpGUuG3TMwnVzZxD2kY`.

NO upstream vector pins: merkle root bytes, sliver BCS bytes, symbol bytes, or per-pair metadata hashes.

Secondary oracles (structural, not byte-level): `blob_encoding.rs:1043` `test_matrix_construction` (row/column source-symbol layout incl. zero-padding); `encoding/utils.rs:59-71` (12-case `compute_symbol_size` table); `config.rs:895` `test_source_symbols_for_n_shards` — `(10,4,7)`, `(100,34,67)`, `(1000,334,667)`; `config.rs:876` `test_encoded_size_reed_solomon`; `config.rs:917` `test_new_for_n_shards`; `merkle.rs:364` `test_n_nodes`; `merkle.rs:463` `test_path_length`.

`merkle.rs` has NO hardcoded digest values — only `EMPTY_NODE = [0;32]` (`:20`) and domain-separation constants `LEAF_PREFIX = [0]` (`:18`) / `INNER_PREFIX = [1]` (`:19`).

Round-trip-only tests, useless as upstream oracles: `blob_encoding.rs:1076`, `:1093`, `:1151`, `:1191`.

No fixture files exist: no `crates/walrus-core/tests/`, no `.snap`, no `testdata/`, no JSON/hex/binary fixtures. `insta` is not a dev-dependency.

Deterministic generator for building our own vectors: `walrus-test-utils/src/lib.rs:353` `random_data()` uses `StdRng::seed_from_u64(42)`. Reproducing outside Rust needs bit-compatible `rand` StdRng (ChaCha12) — safer to dump bytes from a one-off Rust run.

Also useful: `walrus-core/src/test_utils.rs:285` `blob_metadata()` is fully deterministic (10 pairs of `Node::Digest([i;32])`, `unencoded_length = 62_831`, RS2) and feeds `BlobId::from_sliver_pair_metadata` at `:300`. Running it once and pinning the result gives a metadata→root→blob_id oracle that isolates that stage from RS encoding.

---

## Upstream external crates referenced by ported code

`fastcrypto` (`Blake2b256`, `HashFunction`, `Digest`) — walrus pins git rev `4db0e90c732bbf7420ca20de808b698883148d9c` (`walrus/Cargo.toml:57`); this project uses crates.io `fastcrypto 0.1.11`, confirmed byte-identical for BLS-relevant code. `reed-solomon-simd` 3.1.0. `serde` + `serde_with` 3.20 (needed for `Symbols`' `#[serde_as(as = "Bytes")]`). `enum_dispatch` 0.3. `thiserror`. `tracing`. `base64` (BlobId `Display`).
