#    Copyright Frank V. Castellucci
#    SPDX-License-Identifier: Apache-2.0

# -*- coding: utf-8 -*-

"""Python-side tests for the Walrus encode path and BLS confirmation helpers.

Requires the extension to be built into the active environment first::

    maturin develop

The blob-ID expectation here is authored upstream — it is the same vector
asserted by walrus-core's own ``test_v1_blob_id_stability`` at pinned commit
``14641cc0``. Running it through the Python boundary checks the full FFI path,
not just the Rust internals: the post-encode shard rotation, the raw-bytes
contract, and the attribute surface of the result objects.
"""

import base64

import pytest

import pysui_fastcrypto as pfc

# Upstream vector: walrus-core encoding/blob_encoding.rs test_v1_blob_id_stability
UPSTREAM_BLOB = b"walrus blob id v1 regression test"
UPSTREAM_N_SHARDS = 10
UPSTREAM_BLOB_ID_B64 = "RcU82Mwf-CFkv1LaI_2qcpANwpGUuG3TMwnVzZxD2kY"

DIGEST_BYTES = 32


def _b64url_unpadded(raw: bytes) -> str:
    """Encode as unpadded URL-safe base64, the form Walrus uses in URL paths."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# Fixed BLS12-381 vector: three keypairs signing the same message, generated
# once via `fastcrypto` directly (the same way `bls.rs`'s own Rust tests do)
# and hardcoded here. This crate exposes no signing function to Python, so
# these bytes are the only way the tests below can exercise a genuine
# verify/aggregate round trip through the FFI boundary. Frozen data, not a
# protocol vector — it proves the FFI plumbing calls into `fastcrypto`
# correctly, not anything about Walrus wire-format correctness.
#
# To regenerate: `cargo test --lib print_python_test_vector -- --ignored --nocapture`
# (src/walrus/bls.rs), then paste the printed hex below.
BLS_MESSAGE = b"walrus storage confirmation"
# pylint: disable=line-too-long
BLS_PUBLIC_KEYS = [
    bytes.fromhex("86fa236e1d74d7f4e0505833258d9cf8109d8c6d0d3f7fdeb5f07124771071ebce15dd95fd9945e421be2263d277f7c4"),
    bytes.fromhex("ac91600470572da456a0c73ae1693cc3ee1add243fcaa19553f7efc42d5ede059afd3b6fde4da2fc7fd0b2829ac5456b"),
    bytes.fromhex("8ea3b0269e27b3da4fdeedcfa4c6347d95d463c6b1f4a769babb84d61e5f60f7bbad98c372c20e1556190cc03938530c"),
]
# The 96-byte uncompressed encoding of BLS_PUBLIC_KEYS[0] — the same key, the
# format Walrus actually stores on-chain (`Element<UncompressedG1>`). Derived
# deterministically from the compressed form above (point decompression is
# pure math, not randomness), not independently generated.
BLS_PUBLIC_KEY_0_UNCOMPRESSED = bytes.fromhex("06fa236e1d74d7f4e0505833258d9cf8109d8c6d0d3f7fdeb5f07124771071ebce15dd95fd9945e421be2263d277f7c40610c2b5bded84c3b29cc015d39ce67bf09a7625e0fde5715142f7a0265813d262526c091b6fabfc4b6db8bd345819b8")
BLS_SIGNATURES = [
    bytes.fromhex("a07435357105bd9eb10ff17eab5913362cd1fba0b7276d8fbe13cc6503e237ec525c6d002fdd6d554900426c82684e7c049987bb406dd552d7cead8b0222c06be9b2f4096406f9c49967d596ec8b8b17a0d1372d6246725fcd7fc2d6f04d7d61"),
    bytes.fromhex("8f0b76e592185600ebb090a94f90e29a1f4587a7ea1e409037c66b1c3a6dae7c65597c01e587f77cde06b190235faf6c177f5f93c2ebb5c9d5ef33cf94398219b2954b02d82b6b80ba3730a705175977df727dce5da121fe062cc1c62c8877c9"),
    bytes.fromhex("8ad418d76193ea319773ab6982d60792598bf6b300c99510ae755462aa9bed15388182423dee9ed6bd54fcb7a4206ec20ee0b7c46f2e367691442a28e01cfa036dfd59de571173da9c30004e62d970b2b171527dfb5df1e28fc88b48c62d1f3e"),
]
BLS_AGGREGATE_SIGNATURE = bytes.fromhex("b376c2b75bc3115b9392c2d1d4197dcb9569e5d8820eb51ff1e84e6103378e773a578c965483f1b59b40a12ef988fdf50951e69572849b66259e4ba4717d5e484ab769bfa6b124276d81d7f0b3b8ba866056498abf26916f4581e0d688b29b15")
# pylint: enable=line-too-long


class TestWalrusEncode:
    """Encoding a blob into shard-aligned slivers."""

    def test_blob_id_matches_upstream_vector(self):
        """The blob ID must match the value upstream pins for this input."""
        result = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        assert _b64url_unpadded(result.blob_id) == UPSTREAM_BLOB_ID_B64

    def test_blob_id_and_root_hash_are_raw_bytes(self):
        """Digests cross the boundary as bytes, never base64 or list[int]."""
        result = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        assert isinstance(result.blob_id, bytes)
        assert isinstance(result.root_hash, bytes)
        assert len(result.blob_id) == DIGEST_BYTES
        assert len(result.root_hash) == DIGEST_BYTES

    def test_one_sliver_pair_per_shard(self):
        """The sliver list is indexed by shard, so its length is n_shards."""
        result = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        assert len(result.slivers) == UPSTREAM_N_SHARDS

    def test_sliver_payloads_are_raw_bytes(self):
        """Sliver bodies are raw BCS bytes, usable directly as a PUT body."""
        result = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        for sliver in result.slivers:
            assert isinstance(sliver.primary, bytes)
            assert isinstance(sliver.secondary, bytes)
            assert len(sliver.primary) > 0
            assert len(sliver.secondary) > 0
            assert isinstance(sliver.sliver_pair_index, int)

    def test_pair_indices_are_a_rotation_of_shard_positions(self):
        """Position is shard; the pair index is that shard's rotated counterpart.

        The two differ by a blob-ID-dependent rotation applied after encoding.
        Asserting the permutation is exactly a rotation proves the rotation ran
        and did not merely shuffle: without it every sliver would be sent to the
        wrong storage node, with no local error to signal it.
        """
        result = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        indices = [s.sliver_pair_index for s in result.slivers]

        assert sorted(indices) == list(range(UPSTREAM_N_SHARDS))

        offset = indices[0]
        expected = [(offset + i) % UPSTREAM_N_SHARDS for i in range(UPSTREAM_N_SHARDS)]
        assert indices == expected

    def test_pair_indices_match_the_blob_id_rotation(self):
        """Position i is shard i; the pair index at i is (i - k) mod n, k = blob_id mod n.

        Upstream rotates RIGHT by `blob_id` (big-endian) mod n_shards. Asserting the
        exact permutation — not merely that it IS a rotation — is what catches a
        direction inversion, which would otherwise send every sliver to the wrong node
        with no local error. The preceding test only proves SOME rotation happened;
        this one proves it is the RIGHT one.
        """
        result = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        k = int.from_bytes(result.blob_id, "big") % UPSTREAM_N_SHARDS
        expected = [(i - k) % UPSTREAM_N_SHARDS for i in range(UPSTREAM_N_SHARDS)]
        assert [s.sliver_pair_index for s in result.slivers] == expected

    def test_encoding_is_deterministic(self):
        """The same input must always produce the same blob ID."""
        first = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        second = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        assert first.blob_id == second.blob_id
        assert first.root_hash == second.root_hash

    def test_distinct_blobs_produce_distinct_ids(self):
        """A different payload must not collide with the upstream vector."""
        other = pfc.redstuff_encode(b"a different blob entirely", UPSTREAM_N_SHARDS)
        upstream = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        assert other.blob_id != upstream.blob_id

    def test_zero_shards_rejected(self):
        """n_shards must be positive."""
        with pytest.raises(ValueError):
            pfc.redstuff_encode(UPSTREAM_BLOB, 0)

    @pytest.mark.parametrize("n_shards", [1, 2, 3])
    def test_below_minimum_shards_rejected(self, n_shards: int):
        """n_shards below 4 must raise ValueError, not crash the process.

        Regression for a shard count that satisfied `NonZeroU16` but left
        `max_n_faulty(n_shards) == 0`, which the vendored encoder handled
        with an `.expect()` — an uncatchable `PanicException` rather than
        the `ValueError` the type stub promises.
        """
        with pytest.raises(ValueError):
            pfc.redstuff_encode(UPSTREAM_BLOB, n_shards)

    def test_minimum_shards_boundary_succeeds(self):
        """n_shards=4 is the smallest value RedStuff tolerates; it must succeed.

        Boundary check for the rejection threshold enforced by
        test_below_minimum_shards_rejected — 4 is the first value where
        max_n_faulty(n_shards) >= 1.
        """
        result = pfc.redstuff_encode(UPSTREAM_BLOB, 4)
        assert len(result.slivers) == 4

    def test_empty_blob_succeeds(self):
        """An empty blob is a deliberately supported edge case, not an oversight.

        Upstream Walrus treats a 0-byte blob as a 1-byte symbol size (both
        the Rust encoder and the Move `redstuff.move` contract clamp
        `unencoded_length` to 1 when it's 0, each with their own dedicated
        zero-size test) — this pins the same behavior here.
        """
        result = pfc.redstuff_encode(b"", UPSTREAM_N_SHARDS)
        assert len(result.slivers) == UPSTREAM_N_SHARDS
        for sliver in result.slivers:
            assert len(sliver.primary) > 0
            assert len(sliver.secondary) > 0


class TestWalrusBlobMetadata:
    """The BCS metadata body a node requires before it accepts any sliver."""

    def test_metadata_bcs_is_raw_bytes(self):
        """The payload crosses the boundary as bytes, never base64."""
        result = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        assert isinstance(result.metadata_bcs, bytes)
        assert len(result.metadata_bcs) > 0

    def test_metadata_bcs_is_deterministic(self):
        """The same blob and shard count must produce identical metadata."""
        first = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        second = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        assert first.metadata_bcs == second.metadata_bcs

    def test_metadata_bcs_opens_with_v1_variant(self):
        """BlobMetadata is an enum; V1 is variant 0, so BCS leads with 0x00."""
        result = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        assert result.metadata_bcs[0] == 0x00

    def test_metadata_bcs_encoding_type_is_rs2_on_the_wire(self):
        """The encoding type byte must be 0x01 (RS2), not 0x00.

        `EncodingType` declares `RS2 = 1`, but that is a `repr` discriminant and
        serde ignores it — a derived impl would serialise by variant POSITION,
        and RS2 is the only variant, so position 0. Upstream avoids this by
        routing through `EncodingTypeForSerde`, where index 0 is the deprecated
        RedStuffRaptorQ and index 1 is RS2.

        Dropping that indirection in the vendored copy put 0x00 on the wire and
        every testnet storage node rejected the metadata PUT with 400
        "unable to decode request body as BCS" — the node decoded 0x00 as
        RedStuffRaptorQ, whose TryFrom returns Err. Nothing else in the payload
        was wrong, and no other test could see it.
        """
        result = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        assert result.metadata_bcs[1] == 0x01

    def test_metadata_bcs_carries_unencoded_length(self):
        """Field order is encoding_type, unencoded_length, hashes.

        With the V1 variant tag and a single-byte encoding_type ahead of it,
        unencoded_length is the u64 little-endian at offset 2.
        """
        result = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        unencoded_length = int.from_bytes(result.metadata_bcs[2:10], "little")
        assert unencoded_length == len(UPSTREAM_BLOB)

    def test_metadata_bcs_excludes_the_blob_id(self):
        """The inner BlobMetadata is sent, not the ...WithId wrapper.

        Upstream's handler is typed Bcs<BlobMetadata>. Serialising the wrapper
        would prepend the 32-byte blob ID and be rejected by the node.
        """
        result = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        assert not result.metadata_bcs.startswith(result.blob_id)

    def test_metadata_bcs_grows_with_shard_count(self):
        """One sliver pair hash per shard, so more shards means more bytes."""
        small = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        large = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS * 3)
        assert len(large.metadata_bcs) > len(small.metadata_bcs)

    def test_distinct_blobs_produce_distinct_metadata(self):
        """The hashes cover the encoded data, so payload changes propagate."""
        other = pfc.redstuff_encode(b"a different blob entirely", UPSTREAM_N_SHARDS)
        upstream = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        assert other.metadata_bcs != upstream.metadata_bcs


class TestWalrusConfirmationBytes:
    """The exact byte sequence a storage node signs."""

    EPOCH = 21
    BLOB_ID = bytes([7] * DIGEST_BYTES)
    OBJECT_ID = bytes([42] * DIGEST_BYTES)

    def test_permanent_layout(self):
        """Permanent confirmations are 40 bytes with a known header."""
        encoded = pfc.bls_confirmation_bytes(self.EPOCH, self.BLOB_ID)
        assert isinstance(encoded, bytes)
        assert len(encoded) == 40
        # intent: BLOB_CERT_MSG, version DEFAULT, app id STORAGE
        assert encoded[:3] == bytes([1, 0, 3])
        assert encoded[3:7] == self.EPOCH.to_bytes(4, "little")
        assert encoded[7:39] == self.BLOB_ID
        assert encoded[39] == 0

    def test_deletable_layout(self):
        """Deletable confirmations are 72 bytes and carry the object ID."""
        encoded = pfc.bls_confirmation_bytes(
            self.EPOCH, self.BLOB_ID, self.OBJECT_ID
        )
        assert len(encoded) == 72
        assert encoded[:3] == bytes([1, 0, 3])
        assert encoded[3:7] == self.EPOCH.to_bytes(4, "little")
        assert encoded[7:39] == self.BLOB_ID
        assert encoded[39] == 1
        assert encoded[40:] == self.OBJECT_ID

    def test_permanent_and_deletable_differ(self):
        """The persistence discriminant must actually change the bytes."""
        permanent = pfc.bls_confirmation_bytes(self.EPOCH, self.BLOB_ID)
        deletable = pfc.bls_confirmation_bytes(
            self.EPOCH, self.BLOB_ID, self.OBJECT_ID
        )
        assert permanent != deletable

    def test_epoch_affects_bytes(self):
        """A different epoch produces a different signed message."""
        first = pfc.bls_confirmation_bytes(1, self.BLOB_ID)
        second = pfc.bls_confirmation_bytes(2, self.BLOB_ID)
        assert first != second

    @pytest.mark.parametrize("length", [0, 31, 33, 64])
    def test_bad_blob_id_length_rejected(self, length: int):
        """blob_id must be exactly 32 bytes."""
        with pytest.raises(ValueError):
            pfc.bls_confirmation_bytes(self.EPOCH, bytes(length))

    @pytest.mark.parametrize("length", [0, 31, 33])
    def test_bad_object_id_length_rejected(self, length: int):
        """object_id must be exactly 32 bytes when supplied."""
        with pytest.raises(ValueError):
            pfc.bls_confirmation_bytes(self.EPOCH, self.BLOB_ID, bytes(length))


class TestWalrusBls:
    """BLS12-381 helpers.

    Most cases here cover the Python boundary: argument handling, error
    surfacing, and return types — full aggregation/verification coverage
    lives in the Rust unit tests. A handful of cases use a fixed vector
    (three real keypairs signing the same message, generated once via
    `fastcrypto` directly and hardcoded above) to exercise a genuine
    verify/aggregate round trip through the FFI boundary, since this crate
    exposes no signing function for Python to generate one itself.
    """

    @pytest.mark.parametrize("length", [0, 47, 49, 95, 97])
    def test_g1_compress_rejects_wrong_width(self, length: int):
        """Only 48-byte compressed or 96-byte uncompressed keys are accepted."""
        with pytest.raises(ValueError):
            pfc.bls_g1_compress(bytes(length))

    def test_g1_compress_rejects_invalid_point(self):
        """A correctly sized but invalid G1 encoding must be rejected."""
        with pytest.raises(ValueError):
            pfc.bls_g1_compress(bytes([0xFF] * 96))

    def test_aggregate_rejects_empty_set(self):
        """Aggregating nothing is an error, not an empty signature."""
        with pytest.raises(ValueError):
            pfc.bls_aggregate([])

    def test_aggregate_rejects_malformed_signature(self):
        """Signatures must be 96 bytes."""
        with pytest.raises(ValueError):
            pfc.bls_aggregate([bytes(95)])

    def test_aggregate_verify_rejects_empty_key_set(self):
        """Verification against no signers is an error."""
        with pytest.raises(ValueError):
            pfc.bls_aggregate_verify(bytes(96), [], b"message")

    def test_verify_rejects_malformed_key(self):
        """A malformed public key raises rather than returning False."""
        with pytest.raises(ValueError):
            pfc.bls_verify(bytes(10), bytes(96), b"message")

    def test_fixed_vector_signature_verifies(self):
        """A real signature from the fixed vector verifies against its key."""
        assert pfc.bls_verify(BLS_PUBLIC_KEYS[0], BLS_SIGNATURES[0], BLS_MESSAGE)

    def test_fixed_vector_signature_fails_wrong_message(self):
        """A real signature does not verify against a different message."""
        assert not pfc.bls_verify(
            BLS_PUBLIC_KEYS[0], BLS_SIGNATURES[0], b"a different message"
        )

    def test_fixed_vector_aggregate_verifies(self):
        """Aggregating the fixed vector's signatures over the same message verifies."""
        aggregate = pfc.bls_aggregate(BLS_SIGNATURES)
        assert aggregate == BLS_AGGREGATE_SIGNATURE
        assert pfc.bls_aggregate_verify(aggregate, BLS_PUBLIC_KEYS, BLS_MESSAGE)

    def test_aggregate_verify_rejects_infinity_public_key(self):
        """Padding the signer set with the point at infinity must not verify.

        The G1 subgroup check alone accepts infinity, since it is itself a
        subgroup member. Left unguarded, `bls_aggregate_verify` would absorb
        an infinity "public key" as the additive identity and still return
        True, letting a caller believe more signers certified a message than
        actually did.
        """
        aggregate = pfc.bls_aggregate([BLS_SIGNATURES[0]])
        infinity_public_key = bytes([0xC0] + [0] * 47)

        with pytest.raises(ValueError):
            pfc.bls_aggregate_verify(
                aggregate, [BLS_PUBLIC_KEYS[0], infinity_public_key], BLS_MESSAGE
            )

    def test_aggregate_verify_rejects_duplicate_public_key(self):
        """A duplicated public key must not let one signer count twice."""
        aggregate = pfc.bls_aggregate([BLS_SIGNATURES[0]])

        with pytest.raises(ValueError):
            pfc.bls_aggregate_verify(
                aggregate, [BLS_PUBLIC_KEYS[0], BLS_PUBLIC_KEYS[0]], BLS_MESSAGE
            )

    def test_g1_compress_maps_uncompressed_onchain_key_to_compressed(self):
        """The 96-byte on-chain form compresses to the same 48-byte key.

        This is the primary production use case for `bls_g1_compress` — Walrus
        stores committee keys as `Element<UncompressedG1>` — but every other
        test in this class exercises only the already-compressed 48-byte form.
        """
        assert pfc.bls_g1_compress(BLS_PUBLIC_KEY_0_UNCOMPRESSED) == BLS_PUBLIC_KEYS[0]

    def test_aggregate_verify_accepts_mixed_key_widths(self):
        """A committee read off-chain may mix key-width encodings across members.

        Proves `bls_aggregate_verify` correctly resolves a 96-byte uncompressed
        key alongside 48-byte compressed keys for other signers in the same
        call, rather than only ever being exercised with one width throughout.
        """
        aggregate = pfc.bls_aggregate(BLS_SIGNATURES)
        keys = [BLS_PUBLIC_KEY_0_UNCOMPRESSED, BLS_PUBLIC_KEYS[1], BLS_PUBLIC_KEYS[2]]
        assert pfc.bls_aggregate_verify(aggregate, keys, BLS_MESSAGE)


def _outer_metadata(result: "pfc.RedstuffEncodeResult") -> bytes:
    """Build the metadata-GET shape from an encode result.

    ``RedstuffEncodeResult.metadata_bcs`` is the INNER ``BlobMetadata`` that a
    metadata PUT expects. ``redstuff_verify_metadata`` consumes the OUTER
    ``BlobMetadataWithId`` that a metadata GET returns, which is the same bytes
    behind the raw 32-byte blob ID. Constructing it that way here is deliberate:
    it is the asymmetry callers trip over, pinned as executable code rather than
    prose, and Rust gate E asserts the identical relationship against an
    upstream-generated vector.
    """
    return result.blob_id + result.metadata_bcs


def _primaries(result: "pfc.RedstuffEncodeResult") -> list[bytes]:
    """Every primary sliver from an encode result, in shard order."""
    return [pair.primary for pair in result.slivers]


def _secondaries(result: "pfc.RedstuffEncodeResult") -> list[bytes]:
    """Every secondary sliver from an encode result, in shard order."""
    return [pair.secondary for pair in result.slivers]


def _corrupt(sliver: bytes) -> bytes:
    """Flip the first payload byte of a BCS-encoded sliver.

    Byte 0 is the ULEB128 length prefix, so byte 1 is the first symbol byte —
    changing it keeps the sliver parseable but changes what it decodes to.
    """
    return sliver[:1] + bytes([sliver[1] ^ 0xFF]) + sliver[2:]


# At n_shards=10 the Byzantine parameter f is 3, so the decode thresholds are
# n-2f=4 primary slivers and n-f=7 secondary. Both axes are exercised
# throughout: on the primary axis a sliver's axis-local index and its pair index
# are the same number by construction, so a bad index conversion is invisible
# there and shows up only on the secondary axis.
PRIMARY_THRESHOLD = 4
SECONDARY_THRESHOLD = 7


class TestWalrusDecode:
    """The optimistic decode path — reconstruction without verification."""

    def test_primary_round_trip(self):
        """Exactly n-2f primary slivers reconstruct the blob."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        slivers = _primaries(encoded)[:PRIMARY_THRESHOLD]
        assert (
            pfc.redstuff_decode(slivers, len(UPSTREAM_BLOB), UPSTREAM_N_SHARDS, "primary")
            == UPSTREAM_BLOB
        )

    def test_secondary_round_trip(self):
        """Exactly n-f secondary slivers reconstruct the blob."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        slivers = _secondaries(encoded)[:SECONDARY_THRESHOLD]
        assert (
            pfc.redstuff_decode(slivers, len(UPSTREAM_BLOB), UPSTREAM_N_SHARDS, "secondary")
            == UPSTREAM_BLOB
        )

    def test_returns_immutable_bytes(self):
        """The decoded blob crosses as ``bytes``, not ``bytearray``."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        blob = pfc.redstuff_decode(
            _primaries(encoded)[:PRIMARY_THRESHOLD],
            len(UPSTREAM_BLOB),
            UPSTREAM_N_SHARDS,
            "primary",
        )
        assert isinstance(blob, bytes)

    def test_sliver_order_does_not_matter(self):
        """Each sliver carries its own index, so list order is irrelevant.

        A caller collecting slivers from a concurrent fan-out gets them in
        completion order, not shard order. If order mattered, that would be a
        silent corruption rather than an error.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        slivers = _primaries(encoded)[:PRIMARY_THRESHOLD]
        assert (
            pfc.redstuff_decode(
                list(reversed(slivers)), len(UPSTREAM_BLOB), UPSTREAM_N_SHARDS, "primary"
            )
            == UPSTREAM_BLOB
        )

    def test_extra_slivers_are_ignored(self):
        """Supplying more than the threshold is allowed, not an error."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        assert (
            pfc.redstuff_decode(
                _primaries(encoded), len(UPSTREAM_BLOB), UPSTREAM_N_SHARDS, "primary"
            )
            == UPSTREAM_BLOB
        )

    def test_primary_below_threshold_raises(self):
        """One primary sliver short must fail, not return partial bytes."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        slivers = _primaries(encoded)[: PRIMARY_THRESHOLD - 1]
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_decode(slivers, len(UPSTREAM_BLOB), UPSTREAM_N_SHARDS, "primary")
        assert excinfo.value.args[0] == "decoding_unsuccessful"

    def test_secondary_below_threshold_raises(self):
        """One secondary sliver short must fail."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        slivers = _secondaries(encoded)[: SECONDARY_THRESHOLD - 1]
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_decode(slivers, len(UPSTREAM_BLOB), UPSTREAM_N_SHARDS, "secondary")
        assert excinfo.value.args[0] == "decoding_unsuccessful"

    def test_wrong_axis_slivers_rejected(self):
        """Secondary slivers passed as primary are dropped, then decode fails.

        The two axes have different sliver lengths, so wrong-axis slivers fail
        the length check and are silently dropped — leaving too few to decode.
        This surfaces as ``decoding_unsuccessful``, NOT as a parse error, because
        both axes share one BCS shape and the bytes deserialize fine.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_decode(
                _secondaries(encoded), len(UPSTREAM_BLOB), UPSTREAM_N_SHARDS, "primary"
            )
        assert excinfo.value.args[0] == "decoding_unsuccessful"

    def test_malformed_sliver_bytes_rejected(self):
        """Bytes that are not a BCS sliver raise ``invalid_sliver_bcs``."""
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_decode(
                [b"\xff\xff\xff\xff"], len(UPSTREAM_BLOB), UPSTREAM_N_SHARDS, "primary"
            )
        assert excinfo.value.args[0] == "invalid_sliver_bcs"

    @pytest.mark.parametrize("axis", ["", "Primary", "tertiary", "PRIMARY"])
    def test_invalid_axis_rejected(self, axis: str):
        """The axis string is exact and lowercase; anything else is an error."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_decode(
                _primaries(encoded), len(UPSTREAM_BLOB), UPSTREAM_N_SHARDS, axis
            )
        assert excinfo.value.args[0] == "invalid_axis"

    @pytest.mark.parametrize("n_shards", [0, 1, 2, 3])
    def test_below_minimum_shards_rejected(self, n_shards: int):
        """Decode enforces the same n_shards floor as encode.

        The code differs from encode's error shape deliberately: the decode
        surface uses the ``(code, message)`` 2-tuple every ``bls_*`` function
        uses, while ``redstuff_encode`` still raises a 1-tuple. Backlog #10
        migrates encode.
        """
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_decode([b""], len(UPSTREAM_BLOB), n_shards, "primary")
        assert excinfo.value.args[0] == "invalid_n_shards"

    def test_wrong_blob_size_truncates_silently(self):
        """A wrong ``blob_size`` corrupts the output without raising.

        This is the documented footgun, pinned so it cannot regress into
        something worse. ``blob_size`` is not derivable from the slivers, and a
        value that yields the same symbol size decodes cleanly and then
        truncates to the wrong length. ``RedstuffVerifiedMetadata.unencoded_length``
        is the authenticated source; ``redstuff_decode_and_verify`` catches this.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        slivers = _primaries(encoded)[:PRIMARY_THRESHOLD]
        assert pfc.redstuff_decode(slivers, 10, UPSTREAM_N_SHARDS, "primary") == b"walrus blo"


class TestWalrusVerifiedMetadata:
    """Metadata self-verification and the handle it produces."""

    def test_accepts_the_metadata_get_shape(self):
        """The outer ``...WithId`` verifies and yields a handle."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        assert metadata.blob_id == encoded.blob_id

    def test_handle_carries_length_and_committee_size(self):
        """The handle removes ``blob_size`` and ``n_shards`` from later calls."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        assert metadata.unencoded_length == len(UPSTREAM_BLOB)
        assert metadata.n_shards == UPSTREAM_N_SHARDS

    def test_blob_id_is_raw_bytes(self):
        """The blob ID crosses as raw bytes, matching the encode surface."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        assert isinstance(metadata.blob_id, bytes)
        assert len(metadata.blob_id) == DIGEST_BYTES
        assert _b64url_unpadded(metadata.blob_id) == UPSTREAM_BLOB_ID_B64

    def test_rejects_the_metadata_put_shape(self):
        """Passing ``metadata_bcs`` directly is the expected mistake and must fail.

        ``RedstuffEncodeResult.metadata_bcs`` is the INNER ``BlobMetadata`` sent
        to a metadata PUT. Read as the outer wrapper its first 32 bytes are
        consumed as a blob ID, leaving a byte stream that is not valid metadata.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_verify_metadata(encoded.metadata_bcs, UPSTREAM_N_SHARDS)
        assert excinfo.value.args[0] == "invalid_metadata_bcs"

    def test_rejects_wrong_committee_size(self):
        """Metadata for 10 shards must not verify against a 4-shard committee."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_verify_metadata(_outer_metadata(encoded), 4)
        assert excinfo.value.args[0] == "invalid_hash_count"

    def test_rejects_tampered_blob_id(self):
        """A blob ID that does not match the sliver hashes is rejected."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        outer = _outer_metadata(encoded)
        tampered = bytes([outer[0] ^ 0xFF]) + outer[1:]
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_verify_metadata(tampered, UPSTREAM_N_SHARDS)
        assert excinfo.value.args[0] == "blob_id_mismatch"

    def test_rejects_malformed_bytes(self):
        """Bytes that are not BCS metadata raise ``invalid_metadata_bcs``."""
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_verify_metadata(b"\xff\xff\xff\xff", UPSTREAM_N_SHARDS)
        assert excinfo.value.args[0] == "invalid_metadata_bcs"


class TestWalrusDecodeAndVerify:
    """The safe read path — decode plus proof the bytes are the right blob."""

    def test_primary_round_trip(self):
        """Verified primary decode returns the original blob."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        slivers = _primaries(encoded)[:PRIMARY_THRESHOLD]
        assert pfc.redstuff_decode_and_verify(slivers, metadata, "primary") == UPSTREAM_BLOB

    def test_secondary_round_trip(self):
        """Verified secondary decode returns the original blob."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        slivers = _secondaries(encoded)[:SECONDARY_THRESHOLD]
        assert pfc.redstuff_decode_and_verify(slivers, metadata, "secondary") == UPSTREAM_BLOB

    def test_corrupted_sliver_is_caught(self):
        """A single flipped byte must surface as ``blob_id_mismatch``.

        This is the property the bare ``redstuff_decode`` does NOT have: the
        same input there decodes to different bytes with no error at all.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        slivers = _primaries(encoded)[:PRIMARY_THRESHOLD]
        slivers[0] = _corrupt(slivers[0])
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_decode_and_verify(slivers, metadata, "primary")
        assert excinfo.value.args[0] == "blob_id_mismatch"

    def test_bare_decode_does_not_catch_what_verify_catches(self):
        """The contrast that justifies two exports rather than one.

        The identical corrupted input that raises above returns wrong bytes
        here, silently. If this test ever starts raising, the optimistic path
        has grown a check it is documented not to have.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        slivers = _primaries(encoded)[:PRIMARY_THRESHOLD]
        slivers[0] = _corrupt(slivers[0])
        decoded = pfc.redstuff_decode(
            slivers, len(UPSTREAM_BLOB), UPSTREAM_N_SHARDS, "primary"
        )
        assert decoded != UPSTREAM_BLOB

    def test_below_threshold_raises(self):
        """Too few slivers fails at the decode stage, before verification."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        slivers = _primaries(encoded)[: PRIMARY_THRESHOLD - 1]
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_decode_and_verify(slivers, metadata, "primary")
        assert excinfo.value.args[0] == "decoding_unsuccessful"

    def test_invalid_axis_rejected(self):
        """The axis string is validated before any work is done."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_decode_and_verify(_primaries(encoded), metadata, "tertiary")
        assert excinfo.value.args[0] == "invalid_axis"


class TestWalrusVerifySliver:
    """Per-sliver authentication against verified metadata."""

    def test_valid_primary_sliver_returns_none(self):
        """Success is ``None``, not ``True`` — this export raises on failure."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        assert pfc.redstuff_verify_sliver(_primaries(encoded)[0], metadata, "primary") is None

    def test_every_primary_sliver_verifies(self):
        """All n_shards primary slivers authenticate against the metadata."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        for sliver in _primaries(encoded):
            pfc.redstuff_verify_sliver(sliver, metadata, "primary")

    def test_every_secondary_sliver_verifies(self):
        """All n_shards secondary slivers authenticate against the metadata.

        Load-bearing, and not redundant with the primary case. A sliver's hash
        is looked up by PAIR index, converted from its axis-local index. On the
        primary axis that conversion is the identity; on the secondary axis
        sliver j belongs to pair n_shards-1-j. An implementation that skipped
        the conversion would pass the primary test and reject every honest
        secondary sliver from every storage node.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        for sliver in _secondaries(encoded):
            pfc.redstuff_verify_sliver(sliver, metadata, "secondary")

    def test_corrupted_sliver_raises_merkle_root_mismatch(self):
        """A flipped payload byte is the signal that a node served bad data.

        This is the only code in the set that indicts the serving node; the
        others mean the caller supplied the wrong sliver, axis, or metadata.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        corrupted = _corrupt(_primaries(encoded)[0])
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_verify_sliver(corrupted, metadata, "primary")
        assert excinfo.value.args[0] == "merkle_root_mismatch"

    def test_wrong_axis_raises_size_mismatch(self):
        """A secondary sliver checked as primary fails on length, not hash.

        The two axes hold different symbol counts, so this is caught before any
        Merkle work — and it reports a client error rather than accusing the
        node.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_verify_sliver(_secondaries(encoded)[0], metadata, "primary")
        assert excinfo.value.args[0] == "sliver_size_mismatch"

    def test_malformed_sliver_bytes_rejected(self):
        """Bytes that are not a BCS sliver raise ``invalid_sliver_bcs``."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_verify_sliver(b"\xff\xff\xff\xff", metadata, "primary")
        assert excinfo.value.args[0] == "invalid_sliver_bcs"

    def test_invalid_axis_rejected(self):
        """The axis string is validated before the sliver is parsed."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        with pytest.raises(ValueError) as excinfo:
            pfc.redstuff_verify_sliver(_primaries(encoded)[0], metadata, "tertiary")
        assert excinfo.value.args[0] == "invalid_axis"


def _only_value_error(fn, *args):
    """Call ``fn(*args)`` and assert nothing but ``ValueError`` escapes.

    This is a panic-safety probe, not a behaviour test. The vendored walrus
    code is a verbatim mirror of upstream and keeps upstream's ``.expect()``
    calls, which assume a caller has already validated its inputs -- for
    example ``check_hash``'s "hash must exist if all size checks have been
    performed". Those are made unreachable at the FFI boundary rather than
    removed, because rewriting error handling inside ``src/walrus/vendored/``
    would break the file-for-file diffability the drift check depends on.

    A Rust panic that does reach one surfaces through PyO3 as
    ``PanicException``, which is NOT a ``ValueError`` and so is invisible to
    every ``except ValueError`` a caller writes. This crate has shipped that
    bug once already: an ``n_shards`` below 4 reached an ``.expect()`` deep in
    the vendored encoder. Returning without raising is allowed -- some of these
    inputs are legitimately decodable -- but any other exception type is a
    failure.
    """
    try:
        fn(*args)
    except ValueError as exc:
        assert isinstance(exc.args, tuple) and exc.args, "args must be a non-empty tuple"
        return exc
    except BaseException as exc:  # noqa: BLE001 - deliberately broad; that is the point
        raise AssertionError(
            f"{type(exc).__name__} escaped the FFI boundary. Only ValueError is "
            f"part of the documented contract; a Rust panic arrives as "
            f"PanicException and no caller's `except ValueError` will catch it. "
            f"Original: {exc!r}"
        ) from exc
    return None


def _sample_positions(length: int, count: int = 24) -> list[int]:
    """Evenly spread byte offsets across a buffer, capped for runtime."""
    if length <= count:
        return list(range(length))
    step = length // count
    return [i * step for i in range(count)]


class TestWalrusDecodeAdversarial:
    """Malformed and hostile input must raise ValueError, never panic.

    Decode is the first surface in this crate that parses bytes it did not
    produce. Storage nodes are individually untrusted by design, so every one
    of these inputs is something a malicious or broken node can actually send.
    """

    def test_truncated_metadata_never_panics(self):
        """Every prefix of valid metadata must fail cleanly."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        outer = _outer_metadata(encoded)
        for cut in _sample_positions(len(outer)):
            _only_value_error(pfc.redstuff_verify_metadata, outer[:cut], UPSTREAM_N_SHARDS)

    def test_bitflipped_metadata_never_panics(self):
        """A single corrupted byte anywhere in the metadata must fail cleanly."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        outer = _outer_metadata(encoded)
        for pos in _sample_positions(len(outer)):
            mangled = outer[:pos] + bytes([outer[pos] ^ 0xFF]) + outer[pos + 1 :]
            _only_value_error(pfc.redstuff_verify_metadata, mangled, UPSTREAM_N_SHARDS)

    def test_truncated_sliver_never_panics(self):
        """Every prefix of a valid sliver must fail cleanly on all three paths."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        sliver = _primaries(encoded)[0]
        for cut in _sample_positions(len(sliver)):
            stub = sliver[:cut]
            _only_value_error(
                pfc.redstuff_decode,
                [stub],
                len(UPSTREAM_BLOB),
                UPSTREAM_N_SHARDS,
                "primary",
            )
            _only_value_error(pfc.redstuff_decode_and_verify, [stub], metadata, "primary")
            _only_value_error(pfc.redstuff_verify_sliver, stub, metadata, "primary")

    def test_bitflipped_sliver_never_panics(self):
        """A corrupted byte anywhere in a sliver must fail cleanly, not panic.

        The length prefix and the trailing symbol-size and index fields are the
        interesting positions: corrupting them drives the deserialiser and the
        index arithmetic off the paths the ``.expect()`` calls assume.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        sliver = _primaries(encoded)[0]
        for pos in range(len(sliver)):
            mangled = sliver[:pos] + bytes([sliver[pos] ^ 0xFF]) + sliver[pos + 1 :]
            _only_value_error(
                pfc.redstuff_decode,
                [mangled],
                len(UPSTREAM_BLOB),
                UPSTREAM_N_SHARDS,
                "primary",
            )
            _only_value_error(pfc.redstuff_decode_and_verify, [mangled], metadata, "primary")
            _only_value_error(pfc.redstuff_verify_sliver, mangled, metadata, "primary")

    def test_sliver_with_out_of_range_index_never_panics(self):
        """A sliver claiming index 65535 must be rejected, not indexed with.

        The last two bytes of the BCS encoding are the sliver's own index, and
        it is entirely under a hostile node's control. ``check_hash`` looks the
        hash up by PAIR index -- a different number on the secondary axis -- and
        then ``.expect()``s that it exists.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        for axis, source in (("primary", _primaries), ("secondary", _secondaries)):
            forged = source(encoded)[0][:-2] + b"\xff\xff"
            _only_value_error(pfc.redstuff_verify_sliver, forged, metadata, axis)
            _only_value_error(pfc.redstuff_decode_and_verify, [forged], metadata, axis)

    def test_sliver_with_zero_symbol_size_never_panics(self):
        """Symbol size is a NonZeroU16; a zeroed field must be rejected.

        A zero here would reach division and modulo operations in the vendored
        symbol arithmetic.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        sliver = _primaries(encoded)[0]
        forged = sliver[:-4] + b"\x00\x00" + sliver[-2:]
        _only_value_error(pfc.redstuff_verify_sliver, forged, metadata, "primary")
        _only_value_error(
            pfc.redstuff_decode, [forged], len(UPSTREAM_BLOB), UPSTREAM_N_SHARDS, "primary"
        )

    def test_sliver_claiming_enormous_length_never_panics(self):
        """A length prefix far exceeding the payload must fail cleanly.

        ULEB128 ``0xFF 0xFF 0xFF 0xFF 0x0F`` is 2^32-1. The deserialiser must
        reject it against the actual buffer rather than trying to allocate.
        """
        forged = b"\xff\xff\xff\xff\x0f" + b"AAAA" + b"\x02\x00" + b"\x00\x00"
        _only_value_error(
            pfc.redstuff_decode, [forged], len(UPSTREAM_BLOB), UPSTREAM_N_SHARDS, "primary"
        )

    @pytest.mark.parametrize(
        "blob_size", [0, 1, 2**31, 2**32, 2**53, 2**63, 2**64 - 1]
    )
    def test_extreme_blob_size_never_panics(self, blob_size: int):
        """An absurd blob_size must be rejected, not turned into an allocation."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        slivers = _primaries(encoded)[:PRIMARY_THRESHOLD]
        _only_value_error(
            pfc.redstuff_decode, slivers, blob_size, UPSTREAM_N_SHARDS, "primary"
        )

    def test_negative_blob_size_is_a_type_error_not_a_panic(self):
        """A negative blob_size is a u64 conversion failure, not a panic.

        PyO3 raises OverflowError here rather than ValueError, which is the
        same convention ``bls_confirmation_bytes`` documents for ``epoch``.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        slivers = _primaries(encoded)[:PRIMARY_THRESHOLD]
        with pytest.raises((OverflowError, ValueError)):
            pfc.redstuff_decode(slivers, -1, UPSTREAM_N_SHARDS, "primary")

    def test_empty_sliver_list_never_panics(self):
        """No slivers at all must be decoding_unsuccessful, not a panic."""
        exc = _only_value_error(
            pfc.redstuff_decode, [], len(UPSTREAM_BLOB), UPSTREAM_N_SHARDS, "primary"
        )
        assert exc is not None and exc.args[0] == "decoding_unsuccessful"

    def test_duplicate_slivers_never_panics(self):
        """The same sliver repeated must not be counted toward the threshold.

        A hostile node set could otherwise satisfy the threshold with one
        sliver replayed, and the decoder would be fed a rank-deficient system.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        one = _primaries(encoded)[0]
        exc = _only_value_error(
            pfc.redstuff_decode,
            [one] * (PRIMARY_THRESHOLD + 2),
            len(UPSTREAM_BLOB),
            UPSTREAM_N_SHARDS,
            "primary",
        )
        assert exc is not None and exc.args[0] == "decoding_unsuccessful"

    def test_metadata_from_a_different_blob_never_panics(self):
        """Verifying a sliver against another blob's metadata must fail cleanly."""
        mine = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        other = pfc.redstuff_encode(b"an entirely different blob of bytes", UPSTREAM_N_SHARDS)
        other_md = pfc.redstuff_verify_metadata(_outer_metadata(other), UPSTREAM_N_SHARDS)
        _only_value_error(pfc.redstuff_verify_sliver, _primaries(mine)[0], other_md, "primary")
        _only_value_error(
            pfc.redstuff_decode_and_verify,
            _primaries(mine)[:PRIMARY_THRESHOLD],
            other_md,
            "primary",
        )

    def test_metadata_verified_for_a_different_committee_never_panics(self):
        """Slivers encoded at one n_shards, metadata verified at another.

        The handle carries n_shards precisely so these cannot disagree, but the
        slivers themselves still come from the wire.
        """
        small = pfc.redstuff_encode(UPSTREAM_BLOB, 4)
        big = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        big_md = pfc.redstuff_verify_metadata(_outer_metadata(big), UPSTREAM_N_SHARDS)
        for sliver in _primaries(small):
            _only_value_error(pfc.redstuff_verify_sliver, sliver, big_md, "primary")

    def test_garbage_bytes_never_panic(self):
        """Arbitrary non-BCS input on every entry point."""
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        for payload in (b"", b"\x00", b"\xff" * 64, bytes(range(256))):
            _only_value_error(pfc.redstuff_verify_metadata, payload, UPSTREAM_N_SHARDS)
            _only_value_error(
                pfc.redstuff_decode,
                [payload],
                len(UPSTREAM_BLOB),
                UPSTREAM_N_SHARDS,
                "primary",
            )
            _only_value_error(pfc.redstuff_verify_sliver, payload, metadata, "primary")

    def test_padded_sliver_never_panics(self):
        """A sliver with trailing bytes must be rejected, not panic the decoder.

        This is valid BCS that violates a struct invariant, which is a category
        the truncation and corruption cases above cannot produce — those break
        BCS framing and are caught as ``invalid_sliver_bcs`` by the parser.

        `Symbols` documents "the length of this vector is a multiple of
        `symbol_size`" and `Symbols::new` asserts it, but the derived
        `Deserialize` never calls `new`. `BlobDecoder`'s only filter compares
        `Symbols::len()`, which is FLOOR division, so between 1 and
        `symbol_size - 1` extra bytes pass every check and then panic inside
        the vendored decoder — `.expect("we checked above that the symbol size
        is correct")` on the primary axis, an out-of-range slice on secondary.

        A `PanicException` derives from `BaseException`, so it escapes even
        `except Exception`. Found by security review 2026-09-05; the gate is in
        `ffi.rs::decode_slivers` because the vendored tree stays verbatim.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)

        def pad(sliver: bytes, extra: int) -> bytes:
            """Append `extra` bytes to the symbol data, bumping the ULEB prefix.

            Valid only while the length prefix stays one byte, which holds for
            the small vectors used here.
            """
            return bytes([sliver[0] + extra]) + sliver[1:-4] + bytes(extra) + sliver[-4:]

        for axis, source, threshold in (
            ("primary", _primaries, PRIMARY_THRESHOLD),
            ("secondary", _secondaries, SECONDARY_THRESHOLD),
        ):
            slivers = source(encoded)
            # symbol_size is 2 for this vector, so 1 is the only pad that lands
            # strictly inside a symbol. Padding by exactly symbol_size changes
            # the symbol count and is caught by the existing length filter.
            forged = [pad(slivers[0], 1)] + slivers[1:threshold]

            exc = _only_value_error(
                pfc.redstuff_decode, forged, len(UPSTREAM_BLOB), UPSTREAM_N_SHARDS, axis
            )
            assert exc is not None, f"{axis}: padded sliver was silently accepted"
            assert exc.args[0] == "invalid_sliver_bcs"

            exc = _only_value_error(pfc.redstuff_decode_and_verify, forged, metadata, axis)
            assert exc is not None, f"{axis}: padded sliver was silently accepted"
            assert exc.args[0] == "invalid_sliver_bcs"

    def test_padded_sliver_still_rejected_by_verify_sliver(self):
        """The verify path was already safe; pin that it stays safe.

        `SliverData::has_correct_length` compares the exact byte length rather
        than a floor-divided symbol count, so it rejected the padded sliver
        before the decode-path gate existed. Different code, different reason —
        worth its own assertion so a future change to either cannot quietly
        remove the only remaining check.
        """
        encoded = pfc.redstuff_encode(UPSTREAM_BLOB, UPSTREAM_N_SHARDS)
        metadata = pfc.redstuff_verify_metadata(_outer_metadata(encoded), UPSTREAM_N_SHARDS)
        sliver = _primaries(encoded)[0]
        forged = bytes([sliver[0] + 1]) + sliver[1:-4] + b"\x00" + sliver[-4:]

        exc = _only_value_error(pfc.redstuff_verify_sliver, forged, metadata, "primary")
        assert exc is not None and exc.args[0] == "sliver_size_mismatch"
