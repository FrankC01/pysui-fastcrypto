#    Copyright Frank V. Castellucci
#    SPDX-License-Identifier: Apache-2.0

# -*- coding: utf-8 -*-

"""Type stubs for the ``pysui_fastcrypto`` native extension module.

The extension is compiled Rust and exposes no introspectable Python source, so
these stubs are the only type information available to callers. They are
maintained by hand and must track ``src/lib.rs`` and ``src/walrus/ffi.rs``.
"""

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

    Releases the GIL for the duration of the encode and reads through the
    supplied buffer without copying it first.

    Raises:
        ValueError: if ``n_shards`` is less than 4 (RedStuff requires
            tolerance for at least one fault) or the blob cannot be encoded.
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
    """
    ...

def bls_g1_compress(public_key: bytes) -> bytes:
    """Convert a committee public key to its 48-byte compressed form.

    Accepts the 96-byte uncompressed encoding stored on-chain or an
    already-compressed 48-byte key. Both are subgroup-checked.

    Raises:
        ValueError: if the key is neither width, or is not a valid G1 point.
    """
    ...

def bls_aggregate(signatures: list[bytes]) -> bytes:
    """Aggregate confirmation signatures into a single 96-byte signature.

    Raises:
        ValueError: if the list is empty or any signature is malformed.
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
            an input cannot be parsed.
    """
    ...

def bls_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify a single confirmation signature against one signer's public key.

    Argument order matches ``bls_aggregate_verify``: ``message`` is last.

    Returns:
        ``False`` if the inputs are well formed but the signature does not
        verify.

    Raises:
        ValueError: if an input cannot be parsed.
    """
    ...
