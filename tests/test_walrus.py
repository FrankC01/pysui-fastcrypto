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
    lives in the Rust unit tests. `bls_keygen`/`bls_sign` are
    test-only helpers (no BIP-39/BIP-32 derivation, and unrelated to
    `sign_message`/`sign_digest`, which reject BLS12381) that let a few
    cases here also exercise a genuine sign -> verify/aggregate round trip
    through the FFI boundary.
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
            pfc.bls_verify(bytes(10), b"message", bytes(96))

    def test_keygen_signature_verifies(self):
        """A genuine keygen'd keypair signs, and the signature verifies."""
        public, private = pfc.bls_keygen()
        message = b"walrus storage confirmation"
        signature = pfc.bls_sign(private, message)
        assert pfc.bls_verify(public, message, signature)

    def test_keygen_signature_fails_wrong_message(self):
        """A genuine signature does not verify against a different message."""
        public, private = pfc.bls_keygen()
        signature = pfc.bls_sign(private, b"walrus storage confirmation")
        assert not pfc.bls_verify(public, b"a different message", signature)

    def test_keygen_aggregate_verifies(self):
        """Aggregating genuine signatures over the same message verifies."""
        message = b"walrus storage confirmation"
        keypairs = [pfc.bls_keygen() for _ in range(3)]
        signatures = [pfc.bls_sign(private, message) for _, private in keypairs]
        aggregate = pfc.bls_aggregate(signatures)
        public_keys = [public for public, _ in keypairs]
        assert pfc.bls_aggregate_verify(aggregate, public_keys, message)
