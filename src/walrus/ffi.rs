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
use crate::walrus::vendored::encoding::{
    DecodeError, EncodingAxis, EncodingConfig, Primary, ReedSolomonEncodingConfig, Secondary,
    SliverData, SliverVerificationError, rotate_pairs,
};
use crate::walrus::vendored::messages::{BlobPersistenceType, Confirmation};
use crate::walrus::vendored::metadata::{
    BlobMetadata, BlobMetadataApi as _, UnverifiedBlobMetadataWithId, VerificationError,
    VerifiedBlobMetadataWithId,
};

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
        format!(
            "RedstuffEncodeResult(shards={})",
            self.slivers.bind(py).len()
        )
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

// ---------------------------------------------------------------------------
// Decode surface
// ---------------------------------------------------------------------------

/// A `(code, message)` pair carried out of a GIL-released block.
///
/// `code` is a stable machine-matchable string; `message` is human-readable and
/// is NOT a stability contract. Raised as `ValueError.args`, matching the
/// `bls_*` convention.
type FfiError = (&'static str, String);

/// Which RedStuff axis a decode or verification operates on.
///
/// Upstream selects the axis with a compile-time generic (`EncodingAxis`), which
/// has no Python equivalent. The axis therefore crosses the boundary as a string
/// and is dispatched here into the monomorphised helper for that axis.
#[derive(Copy, Clone)]
enum DecodeAxis {
    Primary,
    Secondary,
}

/// Parses the `axis` argument, or raises `ValueError` with code `"invalid_axis"`.
fn parse_axis(axis: &str) -> PyResult<DecodeAxis> {
    match axis {
        "primary" => Ok(DecodeAxis::Primary),
        "secondary" => Ok(DecodeAxis::Secondary),
        other => Err(PyValueError::new_err((
            "invalid_axis",
            format!(r#"axis must be "primary" or "secondary", got {other:?}"#),
        ))),
    }
}

/// Validates `n_shards` for the decode surface and returns it as a `NonZeroU16`.
///
/// Deliberately duplicates the two checks `redstuff_encode` performs inline
/// rather than sharing one helper. `redstuff_encode` raises a 1-tuple
/// `ValueError`; every function on the decode surface raises the `(code,
/// message)` 2-tuple the `bls_*` functions use. Routing encode through this
/// helper would silently change its already-shipped `args` shape, which is
/// exactly the break backlog item #10 exists to make deliberately. The two
/// collapse into one helper when #10 lands.
fn checked_shards(n_shards: u16) -> PyResult<NonZeroU16> {
    let shards = NonZeroU16::new(n_shards).ok_or_else(|| {
        PyValueError::new_err((
            "invalid_n_shards",
            "n_shards must be greater than zero".to_string(),
        ))
    })?;
    if bft::max_n_faulty(shards) == 0 {
        return Err(PyValueError::new_err((
            "invalid_n_shards",
            format!(
                "n_shards must be at least 4 (RedStuff requires tolerance for at \
                 least one fault); got {n_shards}"
            ),
        )));
    }
    Ok(shards)
}

/// Maps a vendored [`DecodeError`] to its stable Python error code.
fn decode_error_code(error: &DecodeError) -> &'static str {
    match error {
        DecodeError::DataTooLarge => "data_too_large",
        DecodeError::IncompatibleParameters(_) => "incompatible_parameters",
        DecodeError::DecoderError(_) => "decoder_error",
        DecodeError::DecodingUnsuccessful => "decoding_unsuccessful",
        // Never produced here: this crate does not use upstream's
        // `EncodingFactory::decode_and_verify`, and `redstuff_decode_and_verify`
        // raises `blob_id_mismatch` from its own re-encode comparison. Mapped to
        // the same code so the two can never diverge for a caller.
        DecodeError::VerificationError => "blob_id_mismatch",
    }
}

/// Maps a vendored metadata [`VerificationError`] to its stable Python error code.
fn metadata_error_code(error: &VerificationError) -> &'static str {
    match error {
        VerificationError::InvalidHashCount { .. } => "invalid_hash_count",
        VerificationError::BlobIdMismatch => "blob_id_mismatch",
        VerificationError::UnencodedLengthTooLarge => "unencoded_length_too_large",
    }
}

/// Maps a vendored [`SliverVerificationError`] to its stable Python error code.
fn sliver_error_code(error: &SliverVerificationError) -> &'static str {
    match error {
        SliverVerificationError::IndexTooLarge => "index_too_large",
        SliverVerificationError::SliverSizeMismatch => "sliver_size_mismatch",
        SliverVerificationError::SymbolSizeMismatch => "symbol_size_mismatch",
        SliverVerificationError::MerkleRootMismatch => "merkle_root_mismatch",
    }
}

/// Blob metadata that has been verified against its own blob ID.
///
/// Returned by [`redstuff_verify_metadata`] and accepted by
/// [`redstuff_decode_and_verify`] and [`redstuff_verify_sliver`]. Holding the
/// verified metadata in a handle rather than re-passing raw bytes means the
/// verification runs once per blob instead of once per sliver, and makes it
/// structurally impossible to verify metadata under one `n_shards` and then
/// check slivers under another — the committee size travels with the handle.
#[pyclass(module = "pysui_fastcrypto", name = "RedstuffVerifiedMetadata", frozen)]
pub struct RedstuffVerifiedMetadata {
    /// The encoding configuration the metadata was verified against.
    config: EncodingConfig,
    /// The verified metadata, including the blob ID and per-sliver hashes.
    metadata: VerifiedBlobMetadataWithId,
}

#[pymethods]
impl RedstuffVerifiedMetadata {
    /// Raw 32-byte blob ID, recomputed from the metadata and confirmed to match.
    #[getter]
    fn blob_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.metadata.blob_id().0)
    }

    /// Length in bytes of the original, unencoded blob.
    ///
    /// This is the `blob_size` a bare [`redstuff_decode`] call needs, so a
    /// caller that has already verified metadata never has to source it
    /// separately.
    #[getter]
    fn unencoded_length(&self) -> u64 {
        self.metadata.metadata().unencoded_length()
    }

    /// The committee size this metadata was verified against.
    #[getter]
    fn n_shards(&self) -> u16 {
        self.config.n_shards().get()
    }

    fn __repr__(&self) -> String {
        format!(
            "RedstuffVerifiedMetadata(unencoded_length={}, n_shards={})",
            self.unencoded_length(),
            self.n_shards()
        )
    }
}

/// Decodes BCS-encoded slivers of one axis back into the source blob.
fn decode_slivers<E: EncodingAxis>(
    slivers: &[PyBackedBytes],
    blob_size: u64,
    n_shards: NonZeroU16,
) -> Result<Vec<u8>, FfiError> {
    let config = ReedSolomonEncodingConfig::new(n_shards);
    let decoder = config
        .get_blob_decoder::<E>(blob_size)
        .map_err(|e| (decode_error_code(&e), e.to_string()))?;
    let parsed = slivers
        .iter()
        .map(|raw| {
            let sliver: SliverData<E> =
                bcs::from_bytes(raw).map_err(|e| ("invalid_sliver_bcs", e.to_string()))?;
            // `Symbols` documents "the length of this vector is a multiple of
            // `symbol_size`" and `Symbols::new` asserts it — but the derived
            // `Deserialize` never calls `new`, and `BlobDecoder`'s only filter
            // compares `Symbols::len()`, which is FLOOR division. So 1..S-1
            // trailing bytes survive every check and then panic inside the
            // vendored decoder: `.expect("we checked above that the symbol size
            // is correct")` on the primary axis, an out-of-range slice on
            // secondary. A `PanicException` is not a `ValueError` and escapes
            // even `except Exception`, so one hostile node could kill a caller's
            // task rather than being dropped from the read set.
            //
            // The gate lives here, not in the vendored tree, because that tree
            // is a verbatim upstream mirror. Upstream is safe by usage — its
            // clients verify slivers before decoding — but this crate hands the
            // decoder raw bytes off the wire, so establishing the invariant is
            // this boundary's job. Found by security review 2026-09-05.
            if !sliver
                .symbols
                .data()
                .len()
                .is_multiple_of(usize::from(sliver.symbols.symbol_size().get()))
            {
                return Err((
                    "invalid_sliver_bcs",
                    "sliver data length is not a multiple of its symbol size".to_string(),
                ));
            }
            Ok(sliver)
        })
        .collect::<Result<Vec<_>, FfiError>>()?;
    decoder
        .decode(parsed)
        .map_err(|e| (decode_error_code(&e), e.to_string()))
}

/// Verifies one BCS-encoded sliver of a known axis against verified metadata.
fn verify_one_sliver<E: EncodingAxis>(
    raw: &[u8],
    config: &EncodingConfig,
    metadata: &BlobMetadata,
) -> Result<(), FfiError> {
    let sliver: SliverData<E> =
        bcs::from_bytes(raw).map_err(|e| ("invalid_sliver_bcs", e.to_string()))?;
    sliver
        .verify(config, metadata)
        .map_err(|e| (sliver_error_code(&e), e.to_string()))
}

/// Verifies blob metadata against its own blob ID and returns a reusable handle.
///
/// `metadata_bcs` is the OUTER `BlobMetadataWithId` — the body a storage node
/// returns from a metadata GET. This is NOT the same shape as
/// `RedstuffEncodeResult.metadata_bcs`, which is the INNER `BlobMetadata` that
/// the metadata PUT expects. The two differ by a leading 32-byte blob ID, and
/// passing the wrong one fails with code `"invalid_metadata_bcs"`.
///
/// Verification confirms three things: the number of sliver hashes matches the
/// committee size, the unencoded length is encodable under this configuration,
/// and the blob ID recomputed from the sliver hashes matches the one carried in
/// the message. It does NOT authenticate the blob ID itself — the caller must
/// have obtained that from an on-chain source and compared it.
///
/// SECURITY CONTRACT: as with `redstuff_encode`, `n_shards` MUST come from an
/// on-chain-sourced Walrus committee. It is a trust boundary, not a tuning knob.
///
/// On failure, `ValueError.args` is `(code, message)`: `code` is one of
/// `"invalid_n_shards"`, `"invalid_metadata_bcs"`, `"invalid_hash_count"`,
/// `"blob_id_mismatch"`, `"unencoded_length_too_large"`. Match on `code`, not
/// the message text.
#[pyfunction]
#[pyo3(signature = (metadata_bcs, n_shards))]
pub fn redstuff_verify_metadata(
    py: Python<'_>,
    metadata_bcs: PyBackedBytes,
    n_shards: u16,
) -> PyResult<RedstuffVerifiedMetadata> {
    let shards = checked_shards(n_shards)?;
    py.detach(move || -> Result<RedstuffVerifiedMetadata, FfiError> {
        let unverified: UnverifiedBlobMetadataWithId =
            bcs::from_bytes(&metadata_bcs).map_err(|e| ("invalid_metadata_bcs", e.to_string()))?;
        let config = EncodingConfig::new(shards);
        let metadata = unverified
            .verify(&config)
            .map_err(|e| (metadata_error_code(&e), e.to_string()))?;
        Ok(RedstuffVerifiedMetadata { config, metadata })
    })
    .map_err(PyValueError::new_err)
}

/// Reconstructs a blob from slivers, WITHOUT verifying the result.
///
/// This is the optimistic path: it trusts that the slivers came from honest
/// nodes and that `blob_size` and `n_shards` are correct. Nothing here detects a
/// malicious or corrupted sliver — a bad symbol produces a different blob with
/// no error. Use [`redstuff_decode_and_verify`] wherever the source of the
/// slivers is not already trusted.
///
/// `slivers` must all be of the axis named by `axis` — `"primary"` or
/// `"secondary"`. They are BCS-encoded `SliverData`, exactly the bytes a storage
/// node returns from a sliver read, and exactly the bytes
/// `RedstuffSliverPair.primary` / `.secondary` carry. Each sliver's own index
/// travels inside those bytes, so the list order does not matter and gaps are
/// fine; extra slivers past the threshold are ignored, and slivers of the wrong
/// length or symbol size are silently dropped rather than rejected.
///
/// The threshold differs by axis: primary decoding needs `n_shards - 2f`
/// slivers, secondary decoding needs `n_shards - f`, where `f` is the Byzantine
/// parameter. At the production `n_shards = 1000` that is 334 primary or 667
/// secondary. Too few slivers — after the drops above — fails with code
/// `"decoding_unsuccessful"`.
///
/// `blob_size` is the UNENCODED blob length. It is not derivable from the
/// slivers, and a wrong value yields either a decode failure or a
/// wrongly-truncated blob, not an error. `RedstuffVerifiedMetadata.unencoded_length`
/// is the authenticated source for it.
///
/// The GIL is released for the whole decode. Peak memory is roughly the decoded
/// blob plus the provided slivers.
///
/// On failure, `ValueError.args` is `(code, message)`: `code` is one of
/// `"invalid_n_shards"`, `"invalid_axis"`, `"invalid_sliver_bcs"`,
/// `"data_too_large"`, `"incompatible_parameters"`, `"decoder_error"`,
/// `"decoding_unsuccessful"`. Match on `code`, not the message text.
#[pyfunction]
#[pyo3(signature = (slivers, blob_size, n_shards, axis))]
pub fn redstuff_decode<'py>(
    py: Python<'py>,
    slivers: Vec<PyBackedBytes>,
    blob_size: u64,
    n_shards: u16,
    axis: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let shards = checked_shards(n_shards)?;
    let axis = parse_axis(axis)?;
    let blob = py
        .detach(move || match axis {
            DecodeAxis::Primary => decode_slivers::<Primary>(&slivers, blob_size, shards),
            DecodeAxis::Secondary => decode_slivers::<Secondary>(&slivers, blob_size, shards),
        })
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &blob))
}

/// Reconstructs a blob from slivers and proves it is the blob the metadata names.
///
/// Decodes exactly as [`redstuff_decode`] does, then re-encodes the result and
/// checks that the recomputed blob ID matches the one in `metadata`. Because the
/// blob ID commits to every sliver hash, a match proves the decoded bytes are
/// the blob that was originally encoded — any corrupted or forged sliver that
/// changed the output produces a different blob ID.
///
/// This is the safe default for reads from storage nodes, which are untrusted
/// individually. Prefer it to [`redstuff_decode`] unless the slivers are already
/// known-good.
///
/// `blob_size` and `n_shards` are taken from `metadata` rather than passed
/// separately, so they cannot disagree with what was verified.
///
/// Cost: the verification is a full re-encode, so this is roughly twice the work
/// of a bare decode, and peak memory is dominated by the re-encode's ~4.5x
/// RedStuff expansion of the decoded blob — budget roughly 6x the blob size.
/// The GIL is released for decode and verification together.
///
/// On failure, `ValueError.args` is `(code, message)`: `code` is one of
/// `"invalid_axis"`, `"invalid_sliver_bcs"`, `"data_too_large"`,
/// `"incompatible_parameters"`, `"decoder_error"`, `"decoding_unsuccessful"`,
/// `"blob_id_mismatch"`. `"blob_id_mismatch"` means the decode produced the
/// wrong bytes — retry against a different set of nodes. Match on `code`, not
/// the message text.
#[pyfunction]
#[pyo3(signature = (slivers, metadata, axis))]
pub fn redstuff_decode_and_verify<'py>(
    py: Python<'py>,
    slivers: Vec<PyBackedBytes>,
    metadata: &RedstuffVerifiedMetadata,
    axis: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let axis = parse_axis(axis)?;
    let shards = metadata.config.n_shards();
    let blob_size = metadata.metadata.metadata().unencoded_length();
    let expected_blob_id = metadata.metadata.blob_id().0;

    let blob = py
        .detach(move || -> Result<Vec<u8>, FfiError> {
            let blob = match axis {
                DecodeAxis::Primary => decode_slivers::<Primary>(&slivers, blob_size, shards)?,
                DecodeAxis::Secondary => decode_slivers::<Secondary>(&slivers, blob_size, shards)?,
            };

            // Upstream verifies a decode with its `Strict` consistency check.
            // Re-deriving the blob ID from the decoded bytes is equivalent in
            // strength — the blob ID is the Merkle root over every sliver hash —
            // and reuses the already-vendored encode path instead of vendoring a
            // second checker.
            let config = ReedSolomonEncodingConfig::new(shards);
            let encoder = config
                .get_blob_encoder(&blob)
                .map_err(|e| ("data_too_large", e.to_string()))?;
            let (pairs, recomputed) = encoder.encode_with_metadata();
            // The sliver pairs are ~4.5x the blob and are not wanted here; drop
            // them before the comparison rather than at end of scope.
            drop(pairs);

            if recomputed.blob_id().0 != expected_blob_id {
                return Err((
                    "blob_id_mismatch",
                    "the blob ID recomputed from the decoded blob does not match the \
                     verified metadata"
                        .to_string(),
                ));
            }
            Ok(blob)
        })
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &blob))
}

/// Checks one sliver against verified metadata, raising if it does not match.
///
/// Returns `None` on success and raises `ValueError` on any failure. This breaks
/// from `bls_verify`, which returns a bool: a sliver check has four distinct
/// failure modes that a caller must tell apart — a wrong-axis or wrong-length
/// sliver is a client bug, while a Merkle-root mismatch is a dishonest node to
/// be dropped from the read set. A bool would collapse all four, and pairing a
/// bool with exceptions for some cases would be worse still.
///
/// Verifying every sliver before decoding is NOT required, and is the expensive
/// way to read a blob: each call re-encodes the sliver out to `n_shards` symbols
/// and builds a Merkle tree over them. [`redstuff_decode_and_verify`] proves the
/// same property for the whole blob at the cost of one re-encode total. Reach
/// for this function to identify WHICH node served a bad sliver after a decode
/// verification has already failed, or when slivers must be validated as they
/// arrive rather than in a batch.
///
/// The GIL is released for the check, unlike every `bls_*` function, so a caller
/// fanning out across nodes can verify concurrently. Releasing it requires
/// cloning the configuration and metadata out of `metadata` — about 64 KB at
/// `n_shards = 1000`, negligible against the re-encode it precedes.
///
/// On failure, `ValueError.args` is `(code, message)`: `code` is one of
/// `"invalid_axis"`, `"invalid_sliver_bcs"`, `"index_too_large"`,
/// `"sliver_size_mismatch"`, `"symbol_size_mismatch"`, `"merkle_root_mismatch"`.
/// Only `"merkle_root_mismatch"` indicts the serving node; the others indicate
/// the wrong sliver, axis, or metadata was supplied. Match on `code`, not the
/// message text.
#[pyfunction]
#[pyo3(signature = (sliver, metadata, axis))]
pub fn redstuff_verify_sliver(
    py: Python<'_>,
    sliver: PyBackedBytes,
    metadata: &RedstuffVerifiedMetadata,
    axis: &str,
) -> PyResult<()> {
    let axis = parse_axis(axis)?;
    let config = metadata.config.clone();
    let blob_metadata = metadata.metadata.metadata().clone();

    py.detach(move || match axis {
        DecodeAxis::Primary => verify_one_sliver::<Primary>(&sliver, &config, &blob_metadata),
        DecodeAxis::Secondary => verify_one_sliver::<Secondary>(&sliver, &config, &blob_metadata),
    })
    .map_err(PyValueError::new_err)
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
    let encoded = bcs::to_bytes(&confirmation).map_err(|e| PyValueError::new_err(e.to_string()))?;
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
pub fn bls_g1_compress<'py>(py: Python<'py>, public_key: Vec<u8>) -> PyResult<Bound<'py, PyBytes>> {
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
pub fn bls_verify(public_key: Vec<u8>, signature: Vec<u8>, message: Vec<u8>) -> PyResult<bool> {
    bls::verify_single(&public_key, &signature, &message)
        .map_err(|e| PyValueError::new_err((e.code(), e.to_string())))
}
