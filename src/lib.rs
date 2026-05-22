//! pysui-fastcrypto is a python wrapper for fundamental use by pysui crypto functions.
//!
//! Portions of the code in this crate were used from MystenLabs Sui repository
//! pysui-fastcrypto, fastcrypto and Sui code are all licensed under the Apache License, Version 2.0
//!

use anyhow::{anyhow, Result};
use base64ct::Encoding as _;
use bip32::{ChildNumber, DerivationPath, XPrv};
use bip39::{Language, Mnemonic, MnemonicType, Seed};

use fastcrypto::{
    ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature},
    encoding::Bech32,
    hash::{Blake2b256, HashFunction},
    secp256k1::{Secp256k1KeyPair, Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature},
    secp256r1::{Secp256r1KeyPair, Secp256r1PrivateKey, Secp256r1PublicKey, Secp256r1Signature},
    traits::{KeyPair, Signer, ToFromBytes, VerifyingKey},
};
use slip10_ed25519::derive_ed25519_private_key;
use std::str::FromStr;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

type LibError = anyhow::Error;
type DefaultHash = Blake2b256;
const DERIVATION_PATH_COIN_TYPE: u32 = 784;
const DERVIATION_PATH_PURPOSE_ED25519: u32 = 44;
const DERVIATION_PATH_PURPOSE_SECP256K1: u32 = 54;
const DERVIATION_PATH_PURPOSE_SECP256R1: u32 = 74;

trait Encoding {
    fn decode(s: &str) -> Result<Vec<u8>>;
    fn encode<T: AsRef<[u8]>>(data: T) -> String;
}
struct Base64;

impl Encoding for Base64 {
    fn decode(s: &str) -> Result<Vec<u8>, LibError> {
        base64ct::Base64::decode_vec(s).map_err(|_e| anyhow!("Error decoding {s}"))
    }

    fn encode<T: AsRef<[u8]>>(data: T) -> String {
        base64ct::Base64::encode_string(data.as_ref())
    }
}

/// Signature Schemes supported by Sui
#[derive(Clone, Debug, PartialEq, Eq)]
enum SignatureScheme {
    ED25519,
    Secp256k1,
    Secp256r1,
    BLS12381,             // Not supported for user Sui Address.
    MultiSig,             // Handled directly in pysui.
    ZkLoginAuthenticator, // Not supported in pysui.
}

impl SignatureScheme {
    fn flag(&self) -> u8 {
        match self {
            SignatureScheme::ED25519 => 0x00,
            SignatureScheme::Secp256k1 => 0x01,
            SignatureScheme::Secp256r1 => 0x02,
            SignatureScheme::MultiSig => 0x03,
            SignatureScheme::BLS12381 => 0x04,
            SignatureScheme::ZkLoginAuthenticator => 0x05,
        }
    }

    fn from_flag_byte(byte_int: &u8) -> Result<SignatureScheme> {
        match byte_int {
            0x00 => Ok(SignatureScheme::ED25519),
            0x01 => Ok(SignatureScheme::Secp256k1),
            0x02 => Ok(SignatureScheme::Secp256r1),
            0x03 => Ok(SignatureScheme::MultiSig),
            0x04 => Ok(SignatureScheme::BLS12381),
            0x05 => Ok(SignatureScheme::ZkLoginAuthenticator),
            _ => Err(anyhow!("Invalid key scheme")),
        }
    }
}

/// Basic PublicKey
#[derive(Debug, PartialEq, Eq)]
enum SuiPublicKey {
    Ed25519(Ed25519PublicKey),
    Secp256k1(Secp256k1PublicKey),
    Secp256r1(Secp256r1PublicKey),
}

impl SuiPublicKey {
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            SuiPublicKey::Ed25519(pk) => pk.as_bytes().to_vec(),
            SuiPublicKey::Secp256k1(pk) => pk.as_bytes().to_vec(),
            SuiPublicKey::Secp256r1(pk) => pk.as_bytes().to_vec(),
        }
    }
}

/// Keypair for signing
#[derive(Debug, PartialEq, Eq)]
enum SuiKeyPair {
    Ed25519(Ed25519KeyPair),
    Secp256k1(Secp256k1KeyPair),
    Secp256r1(Secp256r1KeyPair),
}

impl SuiKeyPair {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            SuiKeyPair::Ed25519(kp) => kp.sign(msg).as_bytes().to_vec(),
            SuiKeyPair::Secp256k1(kp) => kp.sign(msg).as_bytes().to_vec(),
            SuiKeyPair::Secp256r1(kp) => kp.sign(msg).as_bytes().to_vec(),
        }
    }

    fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            SuiKeyPair::Ed25519(kp) => {
                let msg = Ed25519Signature::from_bytes(signature)?;
                Ok(kp.public().verify(message, &msg)?)
            }
            SuiKeyPair::Secp256k1(kp) => {
                let msg = Secp256k1Signature::from_bytes(signature)?;
                Ok(kp.public().verify(message, &msg)?)
            }
            SuiKeyPair::Secp256r1(kp) => {
                let msg = Secp256r1Signature::from_bytes(signature)?;
                Ok(kp.public().verify(message, &msg)?)
            }
        }
    }

    fn pubkey(&self) -> SuiPublicKey {
        match self {
            SuiKeyPair::Ed25519(kp) => SuiPublicKey::Ed25519(kp.public().clone()),
            SuiKeyPair::Secp256k1(kp) => SuiPublicKey::Secp256k1(kp.public().clone()),
            SuiKeyPair::Secp256r1(kp) => SuiPublicKey::Secp256r1(kp.public().clone()),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        match self {
            SuiKeyPair::Ed25519(_) => SignatureScheme::ED25519,
            SuiKeyPair::Secp256k1(_) => SignatureScheme::Secp256k1,
            SuiKeyPair::Secp256r1(_) => SignatureScheme::Secp256r1,
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        match self {
            SuiKeyPair::Ed25519(kp) => kp.as_bytes().to_vec(),
            SuiKeyPair::Secp256k1(kp) => kp.as_bytes().to_vec(),
            SuiKeyPair::Secp256r1(kp) => kp.as_bytes().to_vec(),
        }
    }
}

/// Construct a SuiKeyPair from seed bytes
fn kp_from_bytes(kscheme: SignatureScheme, seed: &[u8]) -> Result<SuiKeyPair, LibError> {
    match kscheme {
        SignatureScheme::ED25519 => Ok(SuiKeyPair::Ed25519(
            Ed25519KeyPair::from_bytes(seed).map_err(|e| anyhow!("{:?}", e))?,
        )),
        SignatureScheme::Secp256k1 => Ok(SuiKeyPair::Secp256k1(
            Secp256k1KeyPair::from_bytes(seed).map_err(|e| anyhow!("{:?}", e))?,
        )),
        SignatureScheme::Secp256r1 => Ok(SuiKeyPair::Secp256r1(
            Secp256r1KeyPair::from_bytes(seed).map_err(|e| anyhow!("{:?}", e))?,
        )),
        SignatureScheme::BLS12381
        | SignatureScheme::MultiSig
        | SignatureScheme::ZkLoginAuthenticator => Err(anyhow!(
            "key derivation not supported {:?}",
            kscheme
        )),
    }
}

/// Given a keystring, produce a keypair
fn keypair_from_keystring(keystring: String) -> Result<(SignatureScheme, SuiKeyPair), LibError> {
    let decoded = Base64::decode(&keystring)?;
    if decoded.is_empty() {
        return Err(anyhow!("Empty keystring"));
    }
    let kscheme = SignatureScheme::from_flag_byte(&decoded[0])?;
    Ok((kscheme.clone(), kp_from_bytes(kscheme, &decoded[1..])?))
}

/// Validate that the given path is correct in the context of the key scheme
fn validate_path(
    key_scheme: &SignatureScheme,
    path: Option<DerivationPath>,
) -> Result<DerivationPath, LibError> {
    match key_scheme {
        SignatureScheme::ED25519 => {
            if let Some(p) = path {
                // The derivation path must be hardened at all levels with purpose = 44, coin_type = 784
                if let &[purpose, coin_type, account, change, address] = p.as_ref() {
                    if Some(purpose) == ChildNumber::new(DERVIATION_PATH_PURPOSE_ED25519, true).ok()
                        && Some(coin_type)
                            == ChildNumber::new(DERIVATION_PATH_COIN_TYPE, true).ok()
                        && account.is_hardened()
                        && change.is_hardened()
                        && address.is_hardened()
                    {
                        Ok(p)
                    } else {
                        Err(anyhow!("Invalid derivation path {:?}", p))
                    }
                } else {
                    Err(anyhow!("Invalid derivation path {:?}", p))
                }
            } else {
                Ok(format!(
                    "m/{DERVIATION_PATH_PURPOSE_ED25519}'/{DERIVATION_PATH_COIN_TYPE}'/0'/0'/0'"
                )
                .parse()
                .map_err(|_| anyhow!("Cannot parse default ED25519 derivation path"))?)
            }
        }
        SignatureScheme::Secp256k1 => {
            if let Some(p) = path {
                // The derivation path must be hardened at first 3 levels with purpose = 54, coin_type = 784
                if let &[purpose, coin_type, account, change, address] = p.as_ref() {
                    if Some(purpose)
                        == ChildNumber::new(DERVIATION_PATH_PURPOSE_SECP256K1, true).ok()
                        && Some(coin_type)
                            == ChildNumber::new(DERIVATION_PATH_COIN_TYPE, true).ok()
                        && account.is_hardened()
                        && !change.is_hardened()
                        && !address.is_hardened()
                    {
                        Ok(p)
                    } else {
                        Err(anyhow!("Invalid derivation path {:?}", p))
                    }
                } else {
                    Err(anyhow!("Invalid derivation path {:?}", p))
                }
            } else {
                Ok(format!(
                    "m/{DERVIATION_PATH_PURPOSE_SECP256K1}'/{DERIVATION_PATH_COIN_TYPE}'/0'/0/0"
                )
                .parse()
                .map_err(|_| anyhow!("Cannot parse default Secp256k1 derivation path"))?)
            }
        }
        SignatureScheme::Secp256r1 => {
            if let Some(p) = path {
                // The derivation path must be hardened at first 3 levels with purpose = 74, coin_type = 784
                if let &[purpose, coin_type, account, change, address] = p.as_ref() {
                    if Some(purpose)
                        == ChildNumber::new(DERVIATION_PATH_PURPOSE_SECP256R1, true).ok()
                        && Some(coin_type)
                            == ChildNumber::new(DERIVATION_PATH_COIN_TYPE, true).ok()
                        && account.is_hardened()
                        && !change.is_hardened()
                        && !address.is_hardened()
                    {
                        Ok(p)
                    } else {
                        Err(anyhow!("Invalid derivation path {:?}", p))
                    }
                } else {
                    Err(anyhow!("Invalid derivation path {:?}", p))
                }
            } else {
                Ok(format!(
                    "m/{DERVIATION_PATH_PURPOSE_SECP256R1}'/{DERIVATION_PATH_COIN_TYPE}'/0'/0/0"
                )
                .parse()
                .map_err(|_| anyhow!("Cannot parse default Secp256r1 derivation path"))?)
            }
        }
        SignatureScheme::BLS12381
        | SignatureScheme::MultiSig
        | SignatureScheme::ZkLoginAuthenticator => Err(anyhow!(
            "key derivation not supported {:?}",
            key_scheme,
        )),
    }
}

/// Create a BIP 32 derived key from seed
fn derive_key_pair_from_path(
    seed: &[u8],
    derivation_path: Option<DerivationPath>,
    key_scheme: &SignatureScheme,
) -> Result<SuiKeyPair, LibError> {
    let derivation_path = validate_path(key_scheme, derivation_path)?;
    match key_scheme {
        SignatureScheme::ED25519 => {
            let indexes = derivation_path
                .into_iter()
                .map(|i| i.into())
                .collect::<Vec<_>>();
            let derived = derive_ed25519_private_key(seed, &indexes);
            let sk = Ed25519PrivateKey::from_bytes(&derived)
                .map_err(|e| anyhow!("KeyGen error {:?}", e.to_string()))?;
            let kp: Ed25519KeyPair = sk.into();
            Ok(SuiKeyPair::Ed25519(kp))
        }
        SignatureScheme::Secp256k1 => {
            let child_xprv = XPrv::derive_from_path(seed, &derivation_path)
                .map_err(|e| anyhow!("KeyGen error {:?}", e.to_string()))?;
            let kp = Secp256k1KeyPair::from(
                Secp256k1PrivateKey::from_bytes(child_xprv.private_key().to_bytes().as_ref())
                    .map_err(|e| anyhow!("KeyGen error {:?}", e.to_string()))?,
            );
            Ok(SuiKeyPair::Secp256k1(kp))
        }
        SignatureScheme::Secp256r1 => {
            let child_xprv = XPrv::derive_from_path(seed, &derivation_path)
                .map_err(|e| anyhow!("KeyGen error {:?}", e.to_string()))?;
            let kp = Secp256r1KeyPair::from(
                Secp256r1PrivateKey::from_bytes(child_xprv.private_key().to_bytes().as_ref())
                    .map_err(|e| anyhow!("KeyGen error {:?}", e.to_string()))?,
            );
            Ok(SuiKeyPair::Secp256r1(kp))
        }
        SignatureScheme::BLS12381
        | SignatureScheme::MultiSig
        | SignatureScheme::ZkLoginAuthenticator => Err(anyhow!(
            "key derivation not supported {:?}",
            key_scheme
        )),
    }
}

/// Generate a new keypair with optional derivation path and optional mnemonic word length
fn new_keypair(
    scheme: u8,
    derivation_path: Option<String>,
    word_length: Option<String>,
) -> Result<(String, SuiKeyPair)> {
    let scheme = SignatureScheme::from_flag_byte(&scheme)?;
    let dvpath = match derivation_path {
        Some(s) => Some(DerivationPath::from_str(&s).map_err(|e| anyhow!("{}", e))?),
        None => None,
    };
    let mnemonic = Mnemonic::new(parse_word_length(word_length)?, Language::English);
    let seed = Seed::new(&mnemonic, "");
    match derive_key_pair_from_path(seed.as_bytes(), dvpath, &scheme) {
        Ok(kp) => Ok((mnemonic.phrase().to_string(), kp)),
        Err(e) => Err(anyhow!("Failed to generate keypair: {:?}", e)),
    }
}

/// Generate a new keypair with derivation path and mnemonic phrase
fn recover_keypair(scheme: u8, derivation_path: String, phrase: String) -> Result<SuiKeyPair> {
    let scheme = SignatureScheme::from_flag_byte(&scheme)?;
    let dvpath = Some(DerivationPath::from_str(&derivation_path).map_err(|e| anyhow!("{}", e))?);
    match Mnemonic::from_phrase(&phrase, Language::English) {
        Ok(mnemonic) => {
            let seed = Seed::new(&mnemonic, "");
            match derive_key_pair_from_path(seed.as_bytes(), dvpath, &scheme) {
                Ok(kp) => Ok(kp),
                Err(e) => Err(anyhow!("Failed to recover keypair: {:?}", e)),
            }
        }
        Err(e) => Err(anyhow!("Recovery phrase failed: {:?}", e)),
    }
}

/// Find the word length for the mnemonic phrase
fn parse_word_length(s: Option<String>) -> Result<MnemonicType, anyhow::Error> {
    match s {
        None => Ok(MnemonicType::Words12),
        Some(s) => match s.as_str() {
            "12" => Ok(MnemonicType::Words12),
            "15" => Ok(MnemonicType::Words15),
            "18" => Ok(MnemonicType::Words18),
            "21" => Ok(MnemonicType::Words21),
            "24" => Ok(MnemonicType::Words24),
            _ => anyhow::bail!("Invalid word length"),
        },
    }
}

fn py_err(e: impl std::fmt::Display) -> PyErr {
    PyErr::new::<PyValueError, _>(e.to_string())
}

/// Returns a keystring's scheme, public and private key bytes from a Sui keystring.
#[pyfunction]
pub fn keys_from_keystring(in_str: String) -> PyResult<(u8, Vec<u8>, Vec<u8>)> {
    if in_str.is_empty() {
        return Err(py_err("Requires valid keystring"));
    }
    let (scheme, kp) = keypair_from_keystring(in_str).map_err(py_err)?;
    Ok((scheme.flag(), kp.pubkey().as_bytes(), kp.as_bytes()))
}

/// Returns a new mnemonic phrase, public and private key bytes.
#[pyfunction]
#[pyo3(signature = (in_scheme, derv_path=None, word_count=None))]
pub fn generate_new_keypair(
    in_scheme: u8,
    derv_path: Option<String>,
    word_count: Option<String>,
) -> PyResult<(String, Vec<u8>, Vec<u8>)> {
    let (phrase, kp) = new_keypair(in_scheme, derv_path, word_count).map_err(py_err)?;
    Ok((phrase, kp.pubkey().as_bytes(), kp.as_bytes()))
}

/// Returns a mnemonic phrase of word_count words.
#[pyfunction]
#[pyo3(signature = (work_count=None))]
pub fn generate_mnemonic_phrase(work_count: Option<String>) -> PyResult<String> {
    let mnemonic = Mnemonic::new(parse_word_length(work_count).map_err(py_err)?, Language::English);
    Ok(mnemonic.phrase().to_string())
}

/// Returns public and private key bytes from mnemonic phrase and derivation path.
#[pyfunction]
pub fn keys_from_mnemonics(
    scheme: u8,
    derivation_path: String,
    phrase: String,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let kp = recover_keypair(scheme, derivation_path, phrase).map_err(py_err)?;
    Ok((kp.pubkey().as_bytes(), kp.as_bytes()))
}

/// Signs a Sui transaction message with optional intent (default [0,0,0]).
/// Output byte layout: scheme_flag (1) | signature_bytes | public_key_bytes.
/// Per-scheme raw signature length: ED25519=64, Secp256k1=64, Secp256r1=64.
#[pyfunction]
#[pyo3(signature = (in_scheme, prv_bytes, in_data, intent=None))]
pub fn sign_digest(
    in_scheme: u8,
    prv_bytes: Vec<u8>,
    in_data: String,
    intent: Option<Vec<u8>>,
) -> PyResult<Vec<u8>> {
    let kp = kp_from_bytes(
        SignatureScheme::from_flag_byte(&in_scheme).map_err(py_err)?,
        &prv_bytes,
    )
    .map_err(py_err)?;
    let intent_msg = intent.unwrap_or_else(|| vec![0, 0, 0]);
    let mut hasher = DefaultHash::default();
    hasher.update(intent_msg);
    hasher.update(Base64::decode(&in_data).map_err(py_err)?);
    let digest = hasher.finalize().digest;
    let mut sig = kp.sign(&digest);
    sig.insert(0, kp.scheme().flag());
    sig.extend(kp.pubkey().as_bytes());
    Ok(sig)
}

/// Signs arbitrary base64 data. Returns a base64 signature string.
#[pyfunction]
pub fn sign_message(in_scheme: u8, prv_bytes: Vec<u8>, in_data: String) -> PyResult<String> {
    let kp = kp_from_bytes(
        SignatureScheme::from_flag_byte(&in_scheme).map_err(py_err)?,
        &prv_bytes,
    )
    .map_err(py_err)?;
    let msg = Base64::decode(&in_data).map_err(py_err)?;
    Ok(Base64::encode(&kp.sign(&msg)))
}

/// Verify signature (base64 string) is valid for data (base64 string) using private key.
#[pyfunction]
pub fn verify(in_scheme: u8, prv_bytes: Vec<u8>, in_data: String, sig: String) -> PyResult<bool> {
    let kp = kp_from_bytes(
        SignatureScheme::from_flag_byte(&in_scheme).map_err(py_err)?,
        &prv_bytes,
    )
    .map_err(py_err)?;
    let data = Base64::decode(&in_data).map_err(py_err)?;
    let sig_bytes = Base64::decode(&sig).map_err(py_err)?;
    Ok(kp.verify_signature(&data, &sig_bytes).is_ok())
}

/// Verify signature (base64 string) is valid for data (base64 string) using public key.
/// sig must be raw signature bytes (base64-encoded), not the full sign_digest output.
#[pyfunction]
pub fn verify_pubk(
    in_scheme: u8,
    pub_bytes: Vec<u8>,
    in_data: String,
    sig: String,
) -> PyResult<bool> {
    let scheme = SignatureScheme::from_flag_byte(&in_scheme).map_err(py_err)?;
    let data = Base64::decode(&in_data).map_err(py_err)?;
    let sig_bytes = Base64::decode(&sig).map_err(py_err)?;
    let result = match scheme {
        SignatureScheme::ED25519 => {
            let sui_pub = Ed25519PublicKey::from_bytes(&pub_bytes).map_err(py_err)?;
            let siggy = Ed25519Signature::from_bytes(&sig_bytes).map_err(py_err)?;
            sui_pub.verify(&data, &siggy)
        }
        SignatureScheme::Secp256k1 => {
            let sui_pub = Secp256k1PublicKey::from_bytes(&pub_bytes).map_err(py_err)?;
            let siggy = Secp256k1Signature::from_bytes(&sig_bytes).map_err(py_err)?;
            sui_pub.verify(&data, &siggy)
        }
        SignatureScheme::Secp256r1 => {
            let sui_pub = Secp256r1PublicKey::from_bytes(&pub_bytes).map_err(py_err)?;
            let siggy = Secp256r1Signature::from_bytes(&sig_bytes).map_err(py_err)?;
            sui_pub.verify(&data, &siggy)
        }
        _ => return Err(py_err("scheme not supported")),
    };
    Ok(result.is_ok())
}

/// Decode a bech32 key string to a Sui key set (scheme_flag, pub_bytes, prv_bytes).
/// Returns (255, [], []) on any failure.
#[pyfunction]
pub fn decode_bech32(key_string: String, hrp: String) -> (u8, Vec<u8>, Vec<u8>) {
    let kbytes = match Bech32::decode(&key_string, &hrp) {
        Ok(v) => v,
        Err(_) => return (255, vec![], vec![]),
    };
    match keypair_from_keystring(Base64::encode(kbytes)) {
        Ok((scheme, kp)) => (scheme.flag(), kp.pubkey().as_bytes(), kp.as_bytes()),
        Err(_) => (255, vec![], vec![]),
    }
}

/// Encode a key (scheme_flag | prv_bytes) to bech32.
#[pyfunction]
pub fn encode_bech32(prv_bytes: Vec<u8>, hrp: String) -> String {
    match Bech32::encode(prv_bytes, &hrp) {
        Ok(r) => r,
        Err(_) => String::new(),
    }
}

/// The pysui_fastcrypto module implemented in Rust.
#[pymodule]
fn pysui_fastcrypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(keys_from_keystring, m)?)?;
    m.add_function(wrap_pyfunction!(keys_from_mnemonics, m)?)?;
    m.add_function(wrap_pyfunction!(generate_new_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(generate_mnemonic_phrase, m)?)?;
    m.add_function(wrap_pyfunction!(sign_digest, m)?)?;
    m.add_function(wrap_pyfunction!(sign_message, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(verify_pubk, m)?)?;
    m.add_function(wrap_pyfunction!(decode_bech32, m)?)?;
    m.add_function(wrap_pyfunction!(encode_bech32, m)?)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Existing tests ---

    #[test]
    fn test_scheme_flag_round_trip() {
        for byte in 0u8..=5u8 {
            let scheme = SignatureScheme::from_flag_byte(&byte).unwrap();
            assert_eq!(scheme.flag(), byte);
        }
    }

    #[test]
    fn test_scheme_from_flag_invalid() {
        assert!(SignatureScheme::from_flag_byte(&6).is_err());
        assert!(SignatureScheme::from_flag_byte(&255).is_err());
    }

    #[test]
    fn test_parse_word_length_all() {
        assert!(parse_word_length(None).is_ok());
        assert!(parse_word_length(Some("12".to_string())).is_ok());
        assert!(parse_word_length(Some("15".to_string())).is_ok());
        assert!(parse_word_length(Some("18".to_string())).is_ok());
        assert!(parse_word_length(Some("21".to_string())).is_ok());
        assert!(parse_word_length(Some("24".to_string())).is_ok());
    }

    #[test]
    fn test_parse_word_length_invalid() {
        assert!(parse_word_length(Some("10".to_string())).is_err());
        assert!(parse_word_length(Some("invalid".to_string())).is_err());
    }

    #[test]
    fn test_base64_round_trip() {
        let data = b"hello world";
        let encoded = Base64::encode(data);
        let decoded = Base64::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_decode_invalid() {
        assert!(Base64::decode("!!!invalid!!!").is_err());
    }

    #[test]
    fn test_validate_path_ed25519_default() {
        let path = validate_path(&SignatureScheme::ED25519, None).unwrap();
        assert_eq!(path.as_ref().len(), 5);
    }

    #[test]
    fn test_validate_path_secp256k1_default() {
        let path = validate_path(&SignatureScheme::Secp256k1, None).unwrap();
        assert_eq!(path.as_ref().len(), 5);
    }

    #[test]
    fn test_validate_path_secp256r1_default() {
        let path = validate_path(&SignatureScheme::Secp256r1, None).unwrap();
        assert_eq!(path.as_ref().len(), 5);
    }

    #[test]
    fn test_validate_path_ed25519_invalid_purpose() {
        let invalid_path = "m/45'/784'/0'/0'/0'".parse().unwrap();
        assert!(validate_path(&SignatureScheme::ED25519, Some(invalid_path)).is_err());
    }

    #[test]
    fn test_validate_path_bls_unsupported() {
        assert!(validate_path(&SignatureScheme::BLS12381, None).is_err());
    }

    // --- New error-path tests ---

    #[test]
    fn test_keypair_from_keystring_empty() {
        assert!(keypair_from_keystring(String::new()).is_err());
    }

    #[test]
    fn test_keypair_from_keystring_invalid_base64() {
        assert!(keypair_from_keystring("!!!not_base64!!!".to_string()).is_err());
    }

    #[test]
    fn test_keypair_from_keystring_invalid_scheme() {
        // base64 of [0xFF, 0x01, 0x02] — invalid scheme byte
        let bad = Base64::encode(&[0xFF_u8, 0x01, 0x02]);
        assert!(keypair_from_keystring(bad).is_err());
    }

    #[test]
    fn test_kp_from_bytes_invalid_length() {
        // 31 bytes — wrong length for any scheme
        let bad_seed = vec![0u8; 31];
        assert!(kp_from_bytes(SignatureScheme::ED25519, &bad_seed).is_err());
    }

    #[test]
    fn test_kp_from_bytes_unsupported_scheme() {
        let seed = vec![0u8; 32];
        assert!(kp_from_bytes(SignatureScheme::BLS12381, &seed).is_err());
        assert!(kp_from_bytes(SignatureScheme::MultiSig, &seed).is_err());
    }

    #[test]
    fn test_new_keypair_unsupported_scheme() {
        // scheme byte 4 = BLS12381
        assert!(new_keypair(4, None, None).is_err());
    }

    #[test]
    fn test_recover_keypair_bad_phrase() {
        assert!(recover_keypair(0, "m/44'/784'/0'/0'/0'".to_string(), "not a real phrase".to_string()).is_err());
    }

    #[test]
    fn test_validate_path_secp256k1_invalid_purpose() {
        let invalid_path = "m/44'/784'/0'/0/0".parse().unwrap();
        assert!(validate_path(&SignatureScheme::Secp256k1, Some(invalid_path)).is_err());
    }

    #[test]
    fn test_validate_path_secp256r1_invalid_purpose() {
        let invalid_path = "m/44'/784'/0'/0/0".parse().unwrap();
        assert!(validate_path(&SignatureScheme::Secp256r1, Some(invalid_path)).is_err());
    }
}
