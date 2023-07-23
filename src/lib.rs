use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use bip32::{DerivationPath, XPrv};
use bip39::{Language, Mnemonic, MnemonicType, Seed};

use fastcrypto::{
    ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey},
    secp256k1::{Secp256k1KeyPair, Secp256k1PrivateKey, Secp256k1PublicKey},
    secp256r1::{Secp256r1KeyPair, Secp256r1PrivateKey, Secp256r1PublicKey},
    traits::{KeyPair, Signer, ToFromBytes},
};
use slip10_ed25519::derive_ed25519_private_key;

use std::{collections::VecDeque, str::FromStr};

type LibError = anyhow::Error;
use pyo3::prelude::*;
/// Signature Schemes supported by Sui
#[derive(Debug, PartialEq, Eq)]
pub enum SignatureScheme {
    ED25519,
    Secp256k1,
    Secp256r1,
    BLS12381, // This is currently not supported for user Sui Address.
    MultiSig,
    ZkLoginAuthenticator,
}

impl SignatureScheme {
    /// Get the byte value of a scheme
    pub fn flag(&self) -> u8 {
        match self {
            SignatureScheme::ED25519 => 0x00,
            SignatureScheme::Secp256k1 => 0x01,
            SignatureScheme::Secp256r1 => 0x02,
            SignatureScheme::MultiSig => 0x03,
            SignatureScheme::BLS12381 => 0x04, // This is currently not supported for user Sui Address.
            SignatureScheme::ZkLoginAuthenticator => 0x05,
        }
    }

    /// Return a scheme from a string
    pub fn from_flag(flag: &str) -> Result<SignatureScheme> {
        let byte_int = flag
            .parse::<u8>()
            .map_err(|_| anyhow!("Invalid key scheme".to_string()))?;
        Self::from_flag_byte(&byte_int)
    }

    /// Return a scheme from a bytes
    pub fn from_flag_byte(byte_int: &u8) -> Result<SignatureScheme> {
        match byte_int {
            0x00 => Ok(SignatureScheme::ED25519),
            0x01 => Ok(SignatureScheme::Secp256k1),
            0x02 => Ok(SignatureScheme::Secp256r1),
            0x03 => Ok(SignatureScheme::MultiSig),
            0x04 => Ok(SignatureScheme::BLS12381),
            0x05 => Ok(SignatureScheme::ZkLoginAuthenticator),
            _ => Err(anyhow!("Invalid key scheme".to_string())),
        }
    }
}

/// Basic PublicKey
#[derive(Debug, PartialEq, Eq)]
pub enum SuiPublicKey {
    Ed25519(Ed25519PublicKey),
    Secp256k1(Secp256k1PublicKey),
    Secp256r1(Secp256r1PublicKey),
}

impl SuiPublicKey {
    /// Get bytes for public key
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
pub enum SuiKeyPair {
    Ed25519(Ed25519KeyPair),
    Secp256k1(Secp256k1KeyPair),
    Secp256r1(Secp256r1KeyPair),
}

impl SuiKeyPair {
    /// Sign a blake2b hashed value
    fn sign(self, msg: &[u8]) -> String {
        let msg_sig = match self {
            SuiKeyPair::Ed25519(kp) => kp.sign(msg).to_string(),
            SuiKeyPair::Secp256k1(kp) => kp.sign(msg).to_string(),
            SuiKeyPair::Secp256r1(kp) => kp.sign(msg).to_string(),
        };
        msg_sig
    }
    /// Get the public key of the keypair
    fn pubkey(&self) -> SuiPublicKey {
        match self {
            SuiKeyPair::Ed25519(kp) => SuiPublicKey::Ed25519(kp.public().clone()),
            SuiKeyPair::Secp256k1(kp) => SuiPublicKey::Secp256k1(kp.public().clone()),
            SuiKeyPair::Secp256r1(kp) => SuiPublicKey::Secp256r1(kp.public().clone()),
        }
    }

    /// Get the scheme of the keypair
    fn scheme(&self) -> SignatureScheme {
        match self {
            SuiKeyPair::Ed25519(_) => SignatureScheme::ED25519,
            SuiKeyPair::Secp256k1(_) => SignatureScheme::Secp256k1,
            SuiKeyPair::Secp256r1(_) => SignatureScheme::Secp256r1,
        }
    }

    /// Retrieve the seed bytes
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            SuiKeyPair::Ed25519(kp) => kp.as_bytes().to_vec(),
            SuiKeyPair::Secp256k1(kp) => kp.as_bytes().to_vec(),
            SuiKeyPair::Secp256r1(kp) => kp.as_bytes().to_vec(),
        }
    }
}

/// Given a keystring, produce a keypair
fn keypair_from_keystring(keystring: &String) -> SuiKeyPair {
    let b64b = &mut VecDeque::from(general_purpose::STANDARD_NO_PAD.decode(keystring).unwrap());
    let kscheme = SignatureScheme::from_flag_byte(&b64b.pop_front().unwrap()).unwrap();
    let rembytes = b64b.make_contiguous();
    match kscheme {
        SignatureScheme::ED25519 => {
            SuiKeyPair::Ed25519(Ed25519KeyPair::from_bytes(rembytes).unwrap())
        }
        SignatureScheme::Secp256k1 => {
            SuiKeyPair::Secp256k1(Secp256k1KeyPair::from_bytes(rembytes).unwrap())
        }
        SignatureScheme::Secp256r1 => {
            SuiKeyPair::Secp256r1(Secp256r1KeyPair::from_bytes(rembytes).unwrap())
        }
        SignatureScheme::BLS12381 => todo!(),
        SignatureScheme::MultiSig => todo!(),
        SignatureScheme::ZkLoginAuthenticator => todo!(),
    }
}

/// Create a BIP 32 derived key from seed
fn derive_key_pair_from_path(
    seed: &[u8],
    derivation_path: DerivationPath,
    key_scheme: &SignatureScheme,
) -> Result<SuiKeyPair, LibError> {
    match key_scheme {
        SignatureScheme::ED25519 => {
            let indexes = derivation_path
                .into_iter()
                .map(|i| i.into())
                .collect::<Vec<_>>();
            let derived = derive_ed25519_private_key(seed, &indexes);
            let sk = Ed25519PrivateKey::from_bytes(&derived)
                .map_err(|e| anyhow!(format!("KeyGen error{:?}", e.to_string())))?;
            let kp: Ed25519KeyPair = sk.into();
            Ok(SuiKeyPair::Ed25519(kp))
        }
        SignatureScheme::Secp256k1 => {
            let child_xprv = XPrv::derive_from_path(seed, &derivation_path)
                .map_err(|e| anyhow!(format!("KeyGen error{:?}", e.to_string())))?;
            let kp = Secp256k1KeyPair::from(
                Secp256k1PrivateKey::from_bytes(child_xprv.private_key().to_bytes().as_slice())
                    .map_err(|e| anyhow!(format!("KeyGen error{:?}", e.to_string())))?,
            );
            Ok(SuiKeyPair::Secp256k1(kp))
        }
        SignatureScheme::Secp256r1 => {
            let child_xprv = XPrv::derive_from_path(seed, &derivation_path)
                .map_err(|e| anyhow!(format!("KeyGen error{:?}", e.to_string())))?;
            let kp = Secp256r1KeyPair::from(
                Secp256r1PrivateKey::from_bytes(child_xprv.private_key().to_bytes().as_slice())
                    .map_err(|e| anyhow!(format!("KeyGen error{:?}", e.to_string())))?,
            );
            Ok(SuiKeyPair::Secp256r1(kp))
        }
        SignatureScheme::BLS12381
        | SignatureScheme::MultiSig
        | SignatureScheme::ZkLoginAuthenticator => Err(anyhow!(format!(
            "key derivation not supported {:?}",
            key_scheme
        ))),
    }
}

/// Generate a new keypair with derivation path and optional mnemonic word lengths for phrase
fn new_keypair(
    scheme: u8,
    derivation_path: String,
    word_length: Option<String>,
) -> Result<(SignatureScheme, String, SuiKeyPair)> {
    let scheme = SignatureScheme::from_flag_byte(&scheme).unwrap();
    let dvpath = DerivationPath::from_str(&derivation_path).unwrap();
    let mnemonic = Mnemonic::new(parse_word_length(word_length).unwrap(), Language::English);
    let seed = Seed::new(&mnemonic, "");
    match derive_key_pair_from_path(seed.as_bytes(), dvpath, &scheme) {
        Ok(kp) => Ok((scheme, mnemonic.phrase().to_string(), kp)),
        Err(e) => Err(anyhow!("Failed to generate keypair: {:?}", e)),
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

#[pyfunction]
/// Fetch schema and keypair seed
fn key_from_string(in_str: String) -> (u8, Vec<u8>, Vec<u8>) {
    let kp = keypair_from_keystring(&in_str);
    let scheme_flag = kp.scheme().flag();
    let pub_bytes = kp.pubkey().as_bytes();
    let prv_bytes = kp.as_bytes();
    (scheme_flag, pub_bytes, prv_bytes)
}

#[pyfunction]
/// Create a new keypair and address
fn new_address_and_key(
    in_scheme: u8,
    derv_path: String,
    word_count: Option<String>,
) -> (u8, String, Vec<u8>, Vec<u8>) {
    let (scheme, phrase, kp) = new_keypair(in_scheme, derv_path, word_count).unwrap();
    (scheme.flag(), phrase, kp.pubkey().as_bytes(), kp.as_bytes())
}

/// A Python module implemented in Rust. The name of this function must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn pysui_fastcrypto(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(key_from_string, m)?)?;
    m.add_function(wrap_pyfunction!(new_address_and_key, m)?)?;

    Ok(())
}
