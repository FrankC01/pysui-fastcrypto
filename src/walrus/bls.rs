//    Copyright Frank V. Castellucci
//    SPDX-License-Identifier: Apache-2.0

// -*- coding: utf-8 -*-

//! BLS12-381 `min_pk` operations for Walrus storage confirmations.
//!
//! Walrus committee members are BLS12-381 `min_pk` signers: public keys are G1
//! points, signatures are G2 points. On-chain, committee keys are stored as
//! `Element<UncompressedG1>` — 96 raw bytes — while `fastcrypto`'s `min_pk`
//! implementation expects the 48-byte compressed encoding. This module owns that
//! conversion so that callers never have to perform G1 point serialization.
//!
//! Aggregate verification here sums the signer public keys directly. The Move
//! implementation computes `total_aggregated_key - sum(non_signers)`, which
//! yields the same group element, so no G1 subtraction is required to match
//! on-chain behaviour.

use fastcrypto::bls12381::min_pk::{
    BLS12381AggregateSignature,
    BLS12381PublicKey,
    BLS12381Signature,
};
use fastcrypto::groups::bls12381::{G1Element, G1ElementUncompressed};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::{AggregateAuthenticator, ToFromBytes, VerifyingKey};
use thiserror::Error;

/// Length in bytes of a compressed BLS12-381 G1 public key.
pub(crate) const COMPRESSED_PUBLIC_KEY_LENGTH: usize = 48;

/// Length in bytes of an uncompressed BLS12-381 G1 public key, as stored on-chain.
pub(crate) const UNCOMPRESSED_PUBLIC_KEY_LENGTH: usize = 96;

/// Length in bytes of a BLS12-381 `min_pk` signature (a G2 point).
pub(crate) const SIGNATURE_LENGTH: usize = 96;

/// Errors raised by the BLS12-381 helpers in this module.
#[derive(Debug, Error)]
pub(crate) enum BlsError {
    /// A public key was neither 48 nor 96 bytes long.
    #[error(
        "expected a {COMPRESSED_PUBLIC_KEY_LENGTH}-byte compressed or \
         {UNCOMPRESSED_PUBLIC_KEY_LENGTH}-byte uncompressed G1 public key, got {0} bytes"
    )]
    PublicKeyLength(usize),

    /// A signature was not the expected length.
    #[error("expected a {SIGNATURE_LENGTH}-byte signature, got {0} bytes")]
    SignatureLength(usize),

    /// A public key was well-sized but is not a valid point in the G1 subgroup.
    #[error("invalid BLS12-381 public key: not a valid point in the G1 subgroup")]
    InvalidPublicKey,

    /// A signature was well-sized but could not be parsed as a G2 point.
    #[error("invalid BLS12-381 signature encoding")]
    InvalidSignature,

    /// Aggregation was attempted over an empty signature set.
    #[error("cannot aggregate an empty signature set")]
    EmptySignatureSet,

    /// Verification was attempted against an empty public key set.
    #[error("cannot verify against an empty public key set")]
    EmptyPublicKeySet,

    /// `fastcrypto` rejected the aggregation itself.
    #[error("BLS12-381 signature aggregation failed")]
    AggregationFailed,
}

/// Converts a Walrus committee public key to its 48-byte compressed form.
///
/// Accepts either the 96-byte uncompressed encoding used on-chain or an
/// already-compressed 48-byte key. Both paths are subgroup-checked: the
/// uncompressed path validates during `G1Element::try_from`, and the compressed
/// path validates during `G1Element::from_byte_array`. A key that is the right
/// length but not a valid G1 point is rejected rather than silently accepted.
pub(crate) fn compress_public_key(
    key_bytes: &[u8],
) -> Result<[u8; COMPRESSED_PUBLIC_KEY_LENGTH], BlsError> {
    let element = match key_bytes.len() {
        UNCOMPRESSED_PUBLIC_KEY_LENGTH => {
            let mut raw = [0u8; UNCOMPRESSED_PUBLIC_KEY_LENGTH];
            raw.copy_from_slice(key_bytes);
            // `from_trusted_byte_array` performs no validation; the subsequent
            // `try_from` is what checks the encoding flags, deserialises the
            // point, and confirms G1 subgroup membership.
            let uncompressed = G1ElementUncompressed::from_trusted_byte_array(raw);
            G1Element::try_from(&uncompressed).map_err(|_| BlsError::InvalidPublicKey)?
        }
        COMPRESSED_PUBLIC_KEY_LENGTH => {
            let mut raw = [0u8; COMPRESSED_PUBLIC_KEY_LENGTH];
            raw.copy_from_slice(key_bytes);
            G1Element::from_byte_array(&raw).map_err(|_| BlsError::InvalidPublicKey)?
        }
        other => return Err(BlsError::PublicKeyLength(other)),
    };
    Ok(element.to_byte_array())
}

/// Parses a committee public key of either width into a `fastcrypto` public key.
///
/// The bytes are subgroup-checked by [`compress_public_key`] before being handed
/// to `fastcrypto`, whose own `from_bytes` does not perform that check.
pub(crate) fn parse_public_key(key_bytes: &[u8]) -> Result<BLS12381PublicKey, BlsError> {
    let compressed = compress_public_key(key_bytes)?;
    BLS12381PublicKey::from_bytes(&compressed).map_err(|_| BlsError::InvalidPublicKey)
}

/// Parses a 96-byte BLS12-381 `min_pk` signature.
pub(crate) fn parse_signature(signature_bytes: &[u8]) -> Result<BLS12381Signature, BlsError> {
    if signature_bytes.len() != SIGNATURE_LENGTH {
        return Err(BlsError::SignatureLength(signature_bytes.len()));
    }
    BLS12381Signature::from_bytes(signature_bytes).map_err(|_| BlsError::InvalidSignature)
}

/// Aggregates individual confirmation signatures into a single 96-byte signature.
pub(crate) fn aggregate_signatures(signatures: &[Vec<u8>]) -> Result<Vec<u8>, BlsError> {
    if signatures.is_empty() {
        return Err(BlsError::EmptySignatureSet);
    }
    let parsed = signatures
        .iter()
        .map(|bytes| parse_signature(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let aggregate = BLS12381AggregateSignature::aggregate(&parsed)
        .map_err(|_| BlsError::AggregationFailed)?;
    Ok(aggregate.as_ref().to_vec())
}

/// Verifies an aggregate signature over one message against a set of signers.
///
/// All Walrus confirmation signers sign the identical BCS-encoded `Confirmation`,
/// so this is same-message aggregate verification.
///
/// Returns `Ok(false)` when the inputs are well-formed but the signature does not
/// verify, and `Err` only when an input could not be parsed.
pub(crate) fn aggregate_verify(
    aggregate_signature: &[u8],
    public_keys: &[Vec<u8>],
    message: &[u8],
) -> Result<bool, BlsError> {
    if public_keys.is_empty() {
        return Err(BlsError::EmptyPublicKeySet);
    }
    if aggregate_signature.len() != SIGNATURE_LENGTH {
        return Err(BlsError::SignatureLength(aggregate_signature.len()));
    }
    let aggregate = BLS12381AggregateSignature::from_bytes(aggregate_signature)
        .map_err(|_| BlsError::InvalidSignature)?;
    let keys = public_keys
        .iter()
        .map(|bytes| parse_public_key(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(aggregate.verify(&keys, message).is_ok())
}

/// Verifies a single confirmation signature against one signer's public key.
///
/// Returns `Ok(false)` when the inputs are well-formed but the signature does not
/// verify, and `Err` only when an input could not be parsed.
pub(crate) fn verify_single(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, BlsError> {
    let key = parse_public_key(public_key)?;
    let parsed = parse_signature(signature)?;
    Ok(key.verify(message, &parsed).is_ok())
}

#[cfg(test)]
mod tests {
    use fastcrypto::traits::{KeyPair, Signer};
    use rand::thread_rng;

    use super::*;

    /// Builds a deterministic-length test keypair.
    fn keypair() -> fastcrypto::bls12381::min_pk::BLS12381KeyPair {
        fastcrypto::bls12381::min_pk::BLS12381KeyPair::generate(&mut thread_rng())
    }

    #[test]
    fn compress_round_trips_against_fastcrypto_uncompressed_form() {
        let kp = keypair();
        let compressed = kp.public().as_ref().to_vec();
        assert_eq!(compressed.len(), COMPRESSED_PUBLIC_KEY_LENGTH);

        // Produce the 96-byte on-chain form using fastcrypto's own inverse, then
        // confirm our conversion recovers the identical compressed bytes.
        let element = G1Element::from_byte_array(
            &compressed
                .clone()
                .try_into()
                .expect("48 bytes"),
        )
        .expect("valid point");
        let uncompressed = G1ElementUncompressed::from(&element);
        let uncompressed_bytes = uncompressed.into_byte_array().to_vec();
        assert_eq!(uncompressed_bytes.len(), UNCOMPRESSED_PUBLIC_KEY_LENGTH);

        let recompressed = compress_public_key(&uncompressed_bytes).expect("conversion");
        assert_eq!(recompressed.to_vec(), compressed);
    }

    #[test]
    fn compress_accepts_already_compressed_keys() {
        let kp = keypair();
        let compressed = kp.public().as_ref().to_vec();
        let out = compress_public_key(&compressed).expect("conversion");
        assert_eq!(out.to_vec(), compressed);
    }

    #[test]
    fn compress_rejects_wrong_length() {
        assert!(matches!(
            compress_public_key(&[0u8; 47]),
            Err(BlsError::PublicKeyLength(47))
        ));
        assert!(matches!(
            compress_public_key(&[]),
            Err(BlsError::PublicKeyLength(0))
        ));
    }

    #[test]
    fn compress_rejects_non_subgroup_points() {
        // All-zero uncompressed bytes are not a valid encoded G1 point.
        assert!(matches!(
            compress_public_key(&[0xffu8; UNCOMPRESSED_PUBLIC_KEY_LENGTH]),
            Err(BlsError::InvalidPublicKey)
        ));
    }

    #[test]
    fn single_signature_verifies() {
        let kp = keypair();
        let message = b"walrus storage confirmation";
        let signature = kp.sign(message);
        let pk_bytes = kp.public().as_ref().to_vec();
        let sig_bytes = signature.as_ref().to_vec();

        assert!(verify_single(&pk_bytes, message, &sig_bytes).expect("verify"));
        assert!(!verify_single(&pk_bytes, b"different message", &sig_bytes).expect("verify"));
    }

    #[test]
    fn aggregate_verifies_over_same_message() {
        let message = b"walrus storage confirmation";
        let kps: Vec<_> = (0..3).map(|_| keypair()).collect();

        let signatures: Vec<Vec<u8>> =
            kps.iter().map(|kp| kp.sign(message).as_ref().to_vec()).collect();
        let public_keys: Vec<Vec<u8>> =
            kps.iter().map(|kp| kp.public().as_ref().to_vec()).collect();

        let aggregate = aggregate_signatures(&signatures).expect("aggregate");
        assert_eq!(aggregate.len(), SIGNATURE_LENGTH);
        assert!(aggregate_verify(&aggregate, &public_keys, message).expect("verify"));
        assert!(!aggregate_verify(&aggregate, &public_keys, b"other").expect("verify"));
    }

    #[test]
    fn aggregate_rejects_empty_inputs() {
        assert!(matches!(
            aggregate_signatures(&[]),
            Err(BlsError::EmptySignatureSet)
        ));
        assert!(matches!(
            aggregate_verify(&[0u8; SIGNATURE_LENGTH], &[], b"m"),
            Err(BlsError::EmptyPublicKeySet)
        ));
    }
}
