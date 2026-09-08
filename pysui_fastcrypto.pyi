#    Copyright Frank V. Castellucci
#    SPDX-License-Identifier: Apache-2.0

# -*- coding: utf-8 -*-

"""Type stubs for the ``pysui_fastcrypto`` native extension module.

The extension is compiled Rust and exposes no introspectable Python source, so
these stubs are the only type information available to callers. They are
maintained by hand and must track ``src/lib.rs`` and ``src/walrus/ffi.rs``.
"""

from typing import Literal

# ---------------------------------------------------------------------------
# Sui key, signing and encoding primitives
# ---------------------------------------------------------------------------

def keys_from_keystring(in_str: str) -> tuple[int, bytes, bytes]:
    """Decode a Sui base64 keystring into ``(scheme_flag, public, private)``."""
    ...

def generate_new_keypair(
    in_scheme: int,
    derv_path: str | None = None,
    word_count: str | None = None,
) -> tuple[str, bytes, bytes]:
    """Generate a mnemonic and keypair, returning ``(phrase, public, private)``."""
    ...

def generate_mnemonic_phrase(work_count: str | None = None) -> str:
    """Generate a BIP-39 mnemonic phrase.

    NOTE: the keyword is ``work_count``, not ``word_count`` — a pre-existing
    spelling inconsistency with :func:`generate_new_keypair`, which uses
    ``word_count``. Renaming it would break callers, so the stub documents the
    behaviour as implemented.
    """
    ...

def keys_from_mnemonics(
    scheme: int,
    derivation_path: str,
    phrase: str,
) -> tuple[bytes, bytes]:
    """Recover ``(public, private)`` from a mnemonic phrase."""
    ...

def sign_digest(
    in_scheme: int,
    prv_bytes: bytes,
    in_data: str,
    intent: bytes | None = None,
) -> bytes:
    """Sign a Sui transaction, returning ``flag | signature | public_key``.

    ``in_data`` is base64. The intent defaults to ``[0, 0, 0]`` and is prepended
    before Blake2b-256 hashing.
    """
    ...

def sign_message(in_scheme: int, prv_bytes: bytes, in_data: str) -> str:
    """Sign arbitrary base64 data with no intent or hash wrapping."""
    ...

def verify(in_scheme: int, prv_bytes: bytes, in_data: str, sig: str) -> bool:
    """Verify a signature using the private key."""
    ...

def verify_pubk(in_scheme: int, pub_bytes: bytes, in_data: str, sig: str) -> bool:
    """Verify a signature using only the public key."""
    ...

def decode_bech32(key_string: str, hrp: str) -> tuple[int, bytes, bytes]:
    """Decode a bech32 key into ``(scheme_flag, public, private)``."""
    ...

def encode_bech32(prv_bytes: bytes, hrp: str) -> str:
    """Encode a private key as bech32."""
    ...

# ---------------------------------------------------------------------------
# Walrus blob encoding and BLS12-381 confirmations
# ---------------------------------------------------------------------------

class RedstuffSliverPair:
    """One shard's share of an encoded blob.

    RedStuff encodes along two axes and a storage node holds both slivers for
    the shard it is assigned.
    """

    @property
    def sliver_pair_index(self) -> int:
        """Index for the sliver PUT URL path.

        This is NOT the shard index. The two differ by a blob-ID-dependent
        rotation applied after encoding.
        """
        ...

    @property
    def primary(self) -> bytes:
        """BCS-serialised primary sliver, usable directly as a PUT body."""
        ...

    @property
    def secondary(self) -> bytes:
        """BCS-serialised secondary sliver, usable directly as a PUT body."""
        ...

class RedstuffEncodeResult:
    """The result of encoding a blob for Walrus."""

    @property
    def blob_id(self) -> bytes:
        """Raw 32-byte blob ID.

        Returned as raw bytes because callers need it in two encodings:
        unpadded URL-safe base64 for URL paths, and ``u256`` for
        ``register_blob`` Move arguments.
        """
        ...

    @property
    def root_hash(self) -> bytes:
        """Raw 32-byte Merkle root over the sliver pair metadata."""
        ...

    @property
    def metadata_bcs(self) -> bytes:
        """BCS-encoded blob metadata, ready to use directly as a PUT body.

        A storage node will not accept ANY sliver for a blob until this has
        been PUT to that node -- it answers 400 FAILED_PRECONDITION with
        reason METADATA_NOT_FOUND. Send metadata first, per node, then the
        slivers.
        """
        ...

    @property
    def slivers(self) -> list[RedstuffSliverPair]:
        """Per-shard sliver pairs, indexed by shard.

        Entry ``i`` belongs to the storage node holding shard ``i``. This
        alignment is produced by the post-encode rotation; do not re-derive it.
        """
        ...

def redstuff_encode(blob: bytes, n_shards: int) -> RedstuffEncodeResult:
    """Encode a blob with RedStuff, returning shard-aligned slivers and metadata.

    SECURITY CONTRACT: n_shards MUST come from an on-chain-sourced Walrus
    committee, never from untrusted or caller-supplied input. Cost scales with
    n_shards^2, so an attacker-controlled value near the u16 ceiling (65535) can
    consume CPU for an extended, uninterruptible period. The only n_shards value
    in production today (mainnet and testnet) is 1000.

    Releases the GIL for the duration of the encode. A ``bytes`` input is read
    zero-copy through the Python buffer (peak memory ~5.5x the blob size). A
    ``bytearray`` is copied into an owned buffer first, since the zero-copy path
    requires an immutable backing (peak memory ~6.5x the blob size).

    Raises:
        ValueError: if ``n_shards`` is less than 4 (RedStuff requires
            tolerance for at least one fault) or the blob cannot be encoded.
    """
    ...

class RedstuffVerifiedMetadata:
    """Blob metadata that has been verified against its own blob ID.

    Returned by ``redstuff_verify_metadata`` and accepted by
    ``redstuff_decode_and_verify`` and ``redstuff_verify_sliver``. Holding the
    verified metadata in a handle means verification runs once per blob rather
    than once per sliver, and makes it structurally impossible to verify
    metadata under one ``n_shards`` and then check slivers under another — the
    committee size travels with the handle.
    """

    @property
    def blob_id(self) -> bytes:
        """Raw 32-byte blob ID, recomputed from the metadata and confirmed to match."""
        ...

    @property
    def unencoded_length(self) -> int:
        """Length in bytes of the original, unencoded blob.

        This is the ``blob_size`` a bare ``redstuff_decode`` call needs, so a
        caller that has already verified metadata never has to source it
        separately.
        """
        ...

    @property
    def n_shards(self) -> int:
        """The committee size this metadata was verified against."""
        ...

def redstuff_verify_metadata(
    metadata_bcs: bytes,
    n_shards: int,
) -> RedstuffVerifiedMetadata:
    """Verify blob metadata against its own blob ID, returning a reusable handle.

    ``metadata_bcs`` is the OUTER ``BlobMetadataWithId`` — the body a storage
    node returns from a metadata GET. This is NOT the same shape as
    ``RedstuffEncodeResult.metadata_bcs``, which is the INNER ``BlobMetadata``
    that the metadata PUT expects. The two differ by a leading 32-byte blob ID,
    and passing the wrong one fails with code ``"invalid_metadata_bcs"``.

    Verification confirms three things: the number of sliver hashes matches the
    committee size, the unencoded length is encodable under this configuration,
    and the blob ID recomputed from the sliver hashes matches the one carried in
    the message. It does NOT authenticate the blob ID itself — the caller must
    have obtained that from an on-chain source and compared it.

    SECURITY CONTRACT: as with ``redstuff_encode``, ``n_shards`` MUST come from
    an on-chain-sourced Walrus committee. It is a trust boundary, not a tuning
    knob.

    Releases the GIL for the verification.

    Raises:
        ValueError: if ``n_shards`` is less than 4, the bytes do not parse, or
            verification fails. ``exc.args`` is ``(code, message)``, where
            ``code`` is one of ``"invalid_n_shards"``,
            ``"invalid_metadata_bcs"``, ``"invalid_hash_count"``,
            ``"blob_id_mismatch"``, ``"unencoded_length_too_large"``. Match on
            ``code``, not the message text.
    """
    ...

def redstuff_decode(
    slivers: list[bytes],
    blob_size: int,
    n_shards: int,
    axis: Literal["primary", "secondary"],
) -> bytes:
    """Reconstruct a blob from slivers, WITHOUT verifying the result.

    This is the optimistic path: it trusts that the slivers came from honest
    nodes and that ``blob_size`` and ``n_shards`` are correct. Nothing here
    detects a malicious or corrupted sliver — a bad symbol produces a different
    blob with no error. Use ``redstuff_decode_and_verify`` wherever the source
    of the slivers is not already trusted.

    ``slivers`` must all be of the axis named by ``axis``. They are BCS-encoded
    slivers: exactly the bytes a storage node returns from a sliver read, and
    exactly the bytes ``RedstuffSliverPair.primary`` / ``.secondary`` carry.
    Each sliver's own index travels inside those bytes, so list order does not
    matter and gaps are fine; extra slivers past the threshold are ignored, and
    slivers of the wrong length or symbol size are silently dropped rather than
    rejected.

    The threshold differs by axis: primary decoding needs ``n_shards - 2f``
    slivers, secondary decoding needs ``n_shards - f``, where ``f`` is the
    Byzantine parameter. At the production ``n_shards = 1000`` that is 334
    primary or 667 secondary. Too few slivers — after the drops above — fails
    with code ``"decoding_unsuccessful"``.

    ``blob_size`` is the UNENCODED blob length. It is not derivable from the
    slivers, and a wrong value yields either a decode failure or a wrongly
    truncated blob, not an error. ``RedstuffVerifiedMetadata.unencoded_length``
    is the authenticated source for it.

    Releases the GIL for the whole decode. Peak memory is roughly the decoded
    blob plus the provided slivers.

    Raises:
        ValueError: if an argument is invalid or decoding fails. ``exc.args``
            is ``(code, message)``, where ``code`` is one of
            ``"invalid_n_shards"``, ``"invalid_axis"``,
            ``"invalid_sliver_bcs"``, ``"data_too_large"``,
            ``"incompatible_parameters"``, ``"decoder_error"``,
            ``"decoding_unsuccessful"``. Match on ``code``, not the message
            text.
    """
    ...

def redstuff_decode_and_verify(
    slivers: list[bytes],
    metadata: RedstuffVerifiedMetadata,
    axis: Literal["primary", "secondary"],
) -> bytes:
    """Reconstruct a blob from slivers and prove it is the blob the metadata names.

    Decodes exactly as ``redstuff_decode`` does, then re-encodes the result and
    checks that the recomputed blob ID matches the one in ``metadata``. Because
    the blob ID commits to every sliver hash, a match proves the decoded bytes
    are the blob that was originally encoded — any corrupted or forged sliver
    that changed the output produces a different blob ID.

    This is the safe default for reads from storage nodes, which are untrusted
    individually. Prefer it to ``redstuff_decode`` unless the slivers are
    already known-good.

    ``blob_size`` and ``n_shards`` are taken from ``metadata`` rather than
    passed separately, so they cannot disagree with what was verified.

    Cost: verification is a full re-encode, so this is roughly twice the work of
    a bare decode, and peak memory is dominated by the re-encode's ~4.5x
    RedStuff expansion of the decoded blob — budget roughly 6x the blob size.
    The GIL is released for decode and verification together.

    Raises:
        ValueError: if an argument is invalid, decoding fails, or the decoded
            blob does not match the metadata. ``exc.args`` is
            ``(code, message)``, where ``code`` is one of ``"invalid_axis"``,
            ``"invalid_sliver_bcs"``, ``"data_too_large"``,
            ``"incompatible_parameters"``, ``"decoder_error"``,
            ``"decoding_unsuccessful"``, ``"blob_id_mismatch"``.
            ``"blob_id_mismatch"`` means the decode produced the wrong bytes —
            retry against a different set of nodes. Match on ``code``, not the
            message text.
    """
    ...

def redstuff_verify_sliver(
    sliver: bytes,
    metadata: RedstuffVerifiedMetadata,
    axis: Literal["primary", "secondary"],
) -> None:
    """Check one sliver against verified metadata, raising if it does not match.

    Returns ``None`` on success and raises ``ValueError`` on any failure. This
    breaks from ``bls_verify``, which returns a bool: a sliver check has four
    distinct failure modes a caller must tell apart — a wrong-axis or
    wrong-length sliver is a client bug, while a Merkle-root mismatch is a
    dishonest node to be dropped from the read set. A bool would collapse all
    four.

    Verifying every sliver before decoding is NOT required, and is the expensive
    way to read a blob: each call re-encodes the sliver out to ``n_shards``
    symbols and builds a Merkle tree over them. ``redstuff_decode_and_verify``
    proves the same property for the whole blob at the cost of one re-encode
    total. Reach for this function to identify WHICH node served a bad sliver
    after a decode verification has already failed, or when slivers must be
    validated as they arrive rather than in a batch.

    Releases the GIL for the check, unlike every ``bls_*`` function, so a caller
    fanning out across nodes can verify concurrently.

    Raises:
        ValueError: if the sliver does not parse or does not verify.
            ``exc.args`` is ``(code, message)``, where ``code`` is one of
            ``"invalid_axis"``, ``"invalid_sliver_bcs"``, ``"index_too_large"``,
            ``"sliver_size_mismatch"``, ``"symbol_size_mismatch"``,
            ``"merkle_root_mismatch"``. Only ``"merkle_root_mismatch"``
            indicts the serving node; the others indicate the wrong sliver,
            axis, or metadata was supplied. Match on ``code``, not the message
            text.
    """
    ...

def bls_confirmation_bytes(
    epoch: int,
    blob_id: bytes,
    object_id: bytes | None = None,
) -> bytes:
    """Return the exact bytes a storage node signs when confirming a blob.

    Pass ``object_id`` for a deletable blob or omit it for a permanent one. The
    result is the BCS-encoded confirmation: 40 bytes permanent, 72 deletable.
    Verifying a confirmation signature requires these exact bytes.

    Raises:
        ValueError: if ``blob_id`` or ``object_id`` is not exactly 32 bytes.
        OverflowError: if ``epoch`` is negative or exceeds a 32-bit unsigned
            range — the underlying type is ``u32``.
    """
    ...

def bls_g1_compress(public_key: bytes) -> bytes:
    """Convert a committee public key to its 48-byte compressed form.

    Accepts the 96-byte uncompressed encoding stored on-chain or an
    already-compressed 48-byte key. Both are subgroup-checked, and the
    point at infinity is explicitly rejected — it is itself a valid G1
    subgroup member, so subgroup-checking alone would accept it.

    Raises:
        ValueError: if the key is neither width, is not a valid G1 point,
            or is the point at infinity. ``exc.args`` is ``(code, message)``,
            where ``code`` is ``"public_key_length"`` or
            ``"invalid_public_key"``. Match on ``code``, not the message
            text, which is not a stability contract.
    """
    ...

def bls_aggregate(signatures: list[bytes]) -> bytes:
    """Aggregate confirmation signatures into a single 96-byte signature.

    Raises:
        ValueError: if the list is empty or any signature is malformed.
            ``exc.args`` is ``(code, message)``, where ``code`` is one of
            ``"empty_signature_set"``, ``"signature_length"``,
            ``"invalid_signature"``, ``"aggregation_failed"``. Match on
            ``code``, not the message text.
    """
    ...

def bls_aggregate_verify(
    aggregate_signature: bytes,
    public_keys: list[bytes],
    message: bytes,
) -> bool:
    """Verify an aggregate signature over one message against a set of signers.

    Public keys may be given in either the 96-byte uncompressed or 48-byte
    compressed form.

    SECURITY CONTRACT: ``public_keys`` must come from an already
    proof-of-possession-validated source — the on-chain Walrus committee.
    This function performs no PoP check itself; passing unvalidated keys
    permits rogue-key forgery. A ``True`` result proves only that the
    aggregate verifies against exactly this key set, not that each key's
    real-world owner signed — derive quorum from on-chain committee
    membership and signer indices, not from ``len(public_keys)``.

    Returns:
        ``False`` if the inputs are well formed but the signature does not
        verify.

    Raises:
        ValueError: if the key set is empty, contains a duplicate key, or
            an input cannot be parsed. ``exc.args`` is ``(code, message)``,
            where ``code`` is one of ``"empty_public_key_set"``,
            ``"public_key_length"``, ``"invalid_public_key"``,
            ``"signature_length"``, ``"invalid_signature"``,
            ``"duplicate_public_key"``. Match on ``code``, not the message
            text.
    """
    ...

def bls_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify a single confirmation signature against one signer's public key.

    Argument order matches ``bls_aggregate_verify``: ``message`` is last.

    Returns:
        ``False`` if the inputs are well formed but the signature does not
        verify.

    Raises:
        ValueError: if an input cannot be parsed. ``exc.args`` is
            ``(code, message)``, where ``code`` is one of
            ``"public_key_length"``, ``"invalid_public_key"``,
            ``"signature_length"``, ``"invalid_signature"``. Match on
            ``code``, not the message text.
    """
    ...
