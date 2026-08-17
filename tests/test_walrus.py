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
    def test_below_minimum_shards_rejected(self, n_shards):
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
    def test_bad_blob_id_length_rejected(self, length):
        """blob_id must be exactly 32 bytes."""
        with pytest.raises(ValueError):
            pfc.bls_confirmation_bytes(self.EPOCH, bytes(length))

    @pytest.mark.parametrize("length", [0, 31, 33])
    def test_bad_object_id_length_rejected(self, length):
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
    def test_g1_compress_rejects_wrong_width(self, length):
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
