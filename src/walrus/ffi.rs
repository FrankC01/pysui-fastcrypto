//    Copyright Frank V. Castellucci
//    SPDX-License-Identifier: Apache-2.0

// -*- coding: utf-8 -*-

//! PyO3 bindings for the Walrus encode path and BLS12-381 confirmation handling.
//!
//! Everything crossing this boundary is raw bytes. Base64 appears only in Walrus
//! URL paths and in confirmation response JSON, never in a sliver PUT body, so
//! encoding here would be wrong on the wire and would force callers to decode
//! back to bytes to build `register_blob` Move arguments.

use std::num::NonZeroU16;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::{PyBytes, PyList};

use crate::walrus::bls;
use crate::walrus::vendored::bft;
use crate::walrus::vendored::core::{BlobId, SuiObjectId};
use crate::walrus::vendored::encoding::{ReedSolomonEncodingConfig, rotate_pairs};
use crate::walrus::vendored::messages::{BlobPersistenceType, Confirmation};
use crate::walrus::vendored::metadata::BlobMetadataApi as _;

/// Length of a blob ID, root hash, or Sui object ID in bytes.
const DIGEST_BYTES: usize = 32;

/// Plain-Rust carrier for one encoded sliver pair, built while the GIL is released.
struct RawSliverPair {
    sliver_pair_index: u16,
    primary: Vec<u8>,
    secondary: Vec<u8>,
}

/// Plain-Rust carrier for a completed encode, built while the GIL is released.
struct RawEncoded {
    blob_id: [u8; DIGEST_BYTES],
    root_hash: [u8; DIGEST_BYTES],
    metadata_bcs: Vec<u8>,
    slivers: Vec<RawSliverPair>,
}

/// Converts a byte vector into a fixed 32-byte array, or raises `ValueError`.
fn to_digest(bytes: &[u8], what: &str) -> PyResult<[u8; DIGEST_BYTES]> {
    if bytes.len() != DIGEST_BYTES {
        return Err(PyValueError::new_err(format!(
            "{what} must be exactly {DIGEST_BYTES} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; DIGEST_BYTES];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// One shard's share of an encoded blob: the primary and secondary slivers.
///
/// RedStuff encodes along two axes, and a storage node holds both slivers for the
/// shard it is assigned. `sliver_pair_index` is the value that belongs in the
/// sliver PUT URL path; it is NOT the shard index, and the two differ by a
/// blob-ID-dependent rotation.
#[pyclass(module = "pysui_fastcrypto", name = "RedstuffSliverPair", frozen)]
pub struct RedstuffSliverPair {
    sliver_pair_index: u16,
    primary: Vec<u8>,
    secondary: Vec<u8>,
}

#[pymethods]
impl RedstuffSliverPair {
    /// The sliver pair index, for use in the sliver PUT URL path.
    #[getter]
    fn sliver_pair_index(&self) -> u16 {
        self.sliver_pair_index
    }

    /// BCS-serialised primary sliver, ready to use directly as a PUT body.
    #[getter]
    fn primary<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.primary)
    }

    /// BCS-serialised secondary sliver, ready to use directly as a PUT body.
    #[getter]
    fn secondary<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.secondary)
    }

    fn __repr__(&self) -> String {
        format!(
            "RedstuffSliverPair(sliver_pair_index={}, primary={} bytes, secondary={} bytes)",
            self.sliver_pair_index,
            self.primary.len(),
            self.secondary.len()
        )
    }
}

/// The result of encoding a blob for Walrus.
///
/// `slivers` is indexed by SHARD: entry `i` belongs to the storage node holding
/// shard `i`. That alignment is produced by applying the blob-ID rotation after
/// encoding, so callers must not re-derive it.
#[pyclass(module = "pysui_fastcrypto", name = "RedstuffEncodeResult", frozen)]
pub struct RedstuffEncodeResult {
    blob_id: [u8; DIGEST_BYTES],
    root_hash: [u8; DIGEST_BYTES],
    metadata_bcs: Vec<u8>,
    slivers: Py<PyList>,
}

#[pymethods]
impl RedstuffEncodeResult {
    /// Raw 32-byte blob ID.
    ///
    /// Callers need this in two encodings — unpadded URL-safe base64 for URL
    /// paths, and `u256` for `register_blob` Move arguments — so raw bytes is the
    /// neutral primitive.
    #[getter]
    fn blob_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.blob_id)
    }

    /// Raw 32-byte Merkle root over the sliver pair metadata.
    #[getter]
    fn root_hash<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.root_hash)
    }

    /// BCS-encoded blob metadata, ready to use directly as a PUT body.
    ///
    /// A storage node will not accept ANY sliver for a blob until this has been
    /// PUT to that node — it answers 400 FAILED_PRECONDITION with reason
    /// METADATA_NOT_FOUND. Send metadata first, per node, then the slivers.
    #[getter]
    fn metadata_bcs<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.metadata_bcs)
    }

    /// Per-shard sliver pairs, indexed by shard.
    ///
    /// Built once at construction and handed out by reference-counted clone, so
    /// repeated access (e.g. indexing in a per-shard upload loop) is O(1) rather
    /// than rebuilding the list on every read.
    #[getter]
    fn slivers(&self, py: Python<'_>) -> Py<PyList> {
        self.slivers.clone_ref(py)
    }

    fn __repr__(&self, py: Python<'_>) -> String {
        format!("RedstuffEncodeResult(shards={})", self.slivers.bind(py).len())
    }
}

/// Encodes a blob with RedStuff and returns shard-aligned slivers plus metadata.
///
/// SECURITY CONTRACT: `n_shards` MUST come from an on-chain-sourced Walrus
/// committee, never from untrusted or attacker-influenced input. This function
/// validates only that `n_shards >= 4`; cost scales with `n_shards^2` (symbol
/// hashing), so an attacker-chosen value near the u16 ceiling (65535) can consume
/// CPU for an extended, uninterruptible period even though no real Walrus network
/// would ever produce such a value. The only n_shards in production today
/// (mainnet and testnet) is 1000.
///
/// `n_shards` must be at least 4: RedStuff needs `max_n_faulty(n_shards) >= 1`
/// to tolerate any fault, which only holds from 4 shards up. Smaller values
/// are rejected here rather than left to fail deep inside the vendored
/// encoder, which panics on an unsupported shard count.
///
/// An empty blob (`blob = b""`) is accepted, not rejected: upstream Walrus
/// treats a 0-byte input as a 1-byte symbol size, in both the Rust encoder
/// (`data_length.max(1)`) and the `redstuff.move` on-chain contract
/// (`if (unencoded_length == 0) { unencoded_length = 1; }`), each with a
/// dedicated zero-size test. This is deliberate upstream behavior, not an
/// oversight here.
///
/// Upload order is not optional: a storage node rejects every sliver for a blob
/// until `metadata_bcs` has been PUT to that node, answering 400
/// FAILED_PRECONDITION with reason METADATA_NOT_FOUND. Send metadata first, per
/// node, then that node's slivers.
///
/// The GIL is released for the whole encode, which is CPU-bound and can be long
/// for large blobs. A `bytes` input is read zero-copy through the Python buffer;
/// a `bytearray` (or other mutable buffer-protocol object) is copied into an
/// owned `bytes` during argument extraction, since the zero-copy path requires
/// an immutable backing to safely cross the GIL release.
///
/// Peak memory is roughly 5.5x the blob size for `bytes` input (RedStuff expands
/// by ~4.5x, and the source blob stays resident alongside the encoded slivers).
/// For `bytearray` input, add one more full copy of the blob: roughly 6.5x. A
/// 1 GiB blob needs about 6 GB (`bytes`) or 7 GB (`bytearray`).
#[pyfunction]
#[pyo3(signature = (blob, n_shards))]
pub fn redstuff_encode(
    py: Python<'_>,
    blob: PyBackedBytes,
    n_shards: u16,
) -> PyResult<RedstuffEncodeResult> {
    let shards = NonZeroU16::new(n_shards)
        .ok_or_else(|| PyValueError::new_err("n_shards must be greater than zero"))?;
    if bft::max_n_faulty(shards) == 0 {
        return Err(PyValueError::new_err(format!(
            "n_shards must be at least 4 (RedStuff requires tolerance for at \
             least one fault); got {n_shards}"
        )));
    }

    let raw = py
        .detach(move || -> Result<RawEncoded, String> {
            let config = ReedSolomonEncodingConfig::new(shards);
            let encoder = config.get_blob_encoder(&blob).map_err(|e| e.to_string())?;
            let (mut pairs, metadata) = encoder.encode_with_metadata();

            // Must run AFTER encoding: the rotation depends on the blob ID, which
            // is only known once the metadata exists. Without it, position i is
            // SliverPairIndex(i), not shard i, and every sliver would be sent to
            // the wrong node with no local error.
            rotate_pairs(&mut pairs, metadata.blob_id()).map_err(|e| e.to_string())?;

            let blob_id = metadata.blob_id().0;
            let root_hash = metadata.metadata().compute_root_hash().bytes();

            // The INNER `BlobMetadata`, not the `…WithId` wrapper: the upstream
            // node handler is typed `Bcs<BlobMetadata>`, and the client sends
            // `metadata.as_ref()`. Serialising the wrapper instead would prepend
            // the blob ID and be rejected. Done here, inside the detached block,
            // so the GIL stays released.
            let metadata_bcs = bcs::to_bytes(metadata.metadata()).map_err(|e| e.to_string())?;

            // Consume `pairs` rather than borrowing it, and drop each pair as soon
            // as it is serialised. BCS output is a full second copy of the encoded
            // data — roughly 4.5x the blob — so holding the source pairs alive for
            // the whole loop doubles peak RSS. Draining keeps only one copy
            // resident: measured on a 1 GiB blob at n_shards=1000, peak RSS falls
            // from 10.89 GB to 6.05 GB with no change in encode time. Switching
            // back to `pairs.iter()` silently reinstates the 2x cost.
            let slivers = pairs
                .into_iter()
                .map(|pair| {
                    let sliver_pair_index = pair.index().0;
                    let primary = bcs::to_bytes(&pair.primary).map_err(|e| e.to_string())?;
                    let secondary = bcs::to_bytes(&pair.secondary).map_err(|e| e.to_string())?;
                    drop(pair);
                    Ok(RawSliverPair {
                        sliver_pair_index,
                        primary,
                        secondary,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;

            Ok(RawEncoded {
                blob_id,
                root_hash,
                metadata_bcs,
                slivers,
            })
        })
        .map_err(PyValueError::new_err)?;

    let slivers = raw
        .slivers
        .into_iter()
        .map(|s| {
            Py::new(
                py,
                RedstuffSliverPair {
                    sliver_pair_index: s.sliver_pair_index,
                    primary: s.primary,
                    secondary: s.secondary,
                },
            )
        })
        .collect::<PyResult<Vec<_>>>()?;
    let slivers = PyList::new(py, slivers)?.unbind();

    Ok(RedstuffEncodeResult {
        blob_id: raw.blob_id,
        root_hash: raw.root_hash,
        metadata_bcs: raw.metadata_bcs,
        slivers,
    })
}

/// Returns the exact bytes a storage node signs when confirming a blob.
///
/// Pass `object_id` for a deletable blob, or omit it for a permanent one. The
/// result is the BCS-encoded `Confirmation`: 40 bytes permanent, 72 deletable.
/// Verifying a confirmation signature requires these exact bytes.
///
/// `epoch` is `u32`; PyO3 raises `OverflowError` (not `ValueError`) if a
/// negative value or one exceeding `u32::MAX` is passed.
#[pyfunction]
#[pyo3(signature = (epoch, blob_id, object_id = None))]
pub fn bls_confirmation_bytes<'py>(
    py: Python<'py>,
    epoch: u32,
    blob_id: Vec<u8>,
    object_id: Option<Vec<u8>>,
) -> PyResult<Bound<'py, PyBytes>> {
    let blob_id = BlobId(to_digest(&blob_id, "blob_id")?);
    let blob_type = match object_id {
        None => BlobPersistenceType::Permanent,
        Some(raw) => BlobPersistenceType::Deletable {
            object_id: SuiObjectId(to_digest(&raw, "object_id")?),
        },
    };
    let confirmation = Confirmation::new(epoch, blob_id, blob_type);
    let encoded =
        bcs::to_bytes(&confirmation).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &encoded))
}

/// Converts a committee public key to its 48-byte compressed form.
///
/// Accepts the 96-byte uncompressed encoding stored on-chain or an
/// already-compressed 48-byte key. Both are subgroup-checked, and the
/// point at infinity is explicitly rejected — it is itself a valid G1
/// subgroup member, so subgroup-checking alone would accept it.
///
/// On failure, `ValueError.args` is `(code, message)`: `code` is a stable
/// machine-matchable string (`"public_key_length"` or `"invalid_public_key"`),
/// `message` is the human-readable description. Match on `code`, not the
/// message text, which is not a stability contract.
#[pyfunction]
#[pyo3(signature = (public_key))]
pub fn bls_g1_compress<'py>(
    py: Python<'py>,
    public_key: Vec<u8>,
) -> PyResult<Bound<'py, PyBytes>> {
    let compressed = bls::compress_public_key(&public_key)
        .map_err(|e| PyValueError::new_err((e.code(), e.to_string())))?;
    Ok(PyBytes::new(py, &compressed))
}

/// Aggregates confirmation signatures into a single 96-byte signature.
///
/// On failure, `ValueError.args` is `(code, message)`: `code` is one of
/// `"empty_signature_set"`, `"signature_length"`, `"invalid_signature"`,
/// `"aggregation_failed"`. Match on `code`, not the message text.
#[pyfunction]
#[pyo3(signature = (signatures))]
pub fn bls_aggregate<'py>(
    py: Python<'py>,
    signatures: Vec<Vec<u8>>,
) -> PyResult<Bound<'py, PyBytes>> {
    let aggregate = bls::aggregate_signatures(&signatures)
        .map_err(|e| PyValueError::new_err((e.code(), e.to_string())))?;
    Ok(PyBytes::new(py, &aggregate))
}

/// Verifies an aggregate signature over one message against a set of signers.
///
/// Public keys may be given in either the 96-byte uncompressed or 48-byte
/// compressed form. Returns `False` for a well-formed signature that does not
/// verify; raises `ValueError` only when an input cannot be parsed or the
/// same public key appears more than once.
///
/// `public_keys` MUST come from an already-proof-of-possession-validated
/// source — the on-chain Walrus committee. This function performs no PoP
/// check itself; passing unvalidated keys permits rogue-key forgery. A
/// `True` result proves only that the aggregate verifies against exactly
/// this key set, not that each key's owner actually signed — derive quorum
/// from on-chain committee membership, not from the length of `public_keys`.
///
/// On failure, `ValueError.args` is `(code, message)`: `code` is one of
/// `"empty_public_key_set"`, `"public_key_length"`, `"invalid_public_key"`,
/// `"signature_length"`, `"invalid_signature"`, `"duplicate_public_key"`.
/// Match on `code`, not the message text.
#[pyfunction]
#[pyo3(signature = (aggregate_signature, public_keys, message))]
pub fn bls_aggregate_verify(
    aggregate_signature: Vec<u8>,
    public_keys: Vec<Vec<u8>>,
    message: Vec<u8>,
) -> PyResult<bool> {
    bls::aggregate_verify(&aggregate_signature, &public_keys, &message)
        .map_err(|e| PyValueError::new_err((e.code(), e.to_string())))
}

/// Verifies a single confirmation signature against one signer's public key.
///
/// Argument order matches `bls_aggregate_verify`: `message` is last.
///
/// Returns `False` for a well-formed signature that does not verify; raises
/// `ValueError` only when an input cannot be parsed.
///
/// On failure, `ValueError.args` is `(code, message)`: `code` is one of
/// `"public_key_length"`, `"invalid_public_key"`, `"signature_length"`,
/// `"invalid_signature"`. Match on `code`, not the message text.
#[pyfunction]
#[pyo3(signature = (public_key, signature, message))]
pub fn bls_verify(
    public_key: Vec<u8>,
    signature: Vec<u8>,
    message: Vec<u8>,
) -> PyResult<bool> {
    bls::verify_single(&public_key, &signature, &message)
        .map_err(|e| PyValueError::new_err((e.code(), e.to_string())))
}
