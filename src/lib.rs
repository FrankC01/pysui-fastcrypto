use anyhow::{anyhow, Result};
use base64ct::Encoding as _;
use bip32::{ChildNumber, DerivationPath, XPrv};
use bip39::{Language, Mnemonic, MnemonicType, Seed};

use fastcrypto::{
    ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey},
    hash::{Blake2b256, HashFunction},
    secp256k1::{Secp256k1KeyPair, Secp256k1PrivateKey, Secp256k1PublicKey},
    secp256r1::{Secp256r1KeyPair, Secp256r1PrivateKey, Secp256r1PublicKey},
    traits::{KeyPair, Signer, ToFromBytes},
};
use slip10_ed25519::derive_ed25519_private_key;
use std::{
    collections::{BTreeMap, VecDeque},
    str::FromStr,
    sync::Mutex,
};

use pyo3::prelude::*;

type LibError = anyhow::Error;
pub type DefaultHash = Blake2b256;
const DERIVATION_PATH_COIN_TYPE: u32 = 784;
const DERVIATION_PATH_PURPOSE_ED25519: u32 = 44;
const DERVIATION_PATH_PURPOSE_SECP256K1: u32 = 54;
const DERVIATION_PATH_PURPOSE_SECP256R1: u32 = 74;

/// Trait representing a general binary-to-string encoding.
pub trait Encoding {
    /// Decode this encoding into bytes.
    fn decode(s: &str) -> Result<Vec<u8>>;
    /// Encode bytes into a string.
    fn encode<T: AsRef<[u8]>>(data: T) -> String;
}
pub struct Base64(String);

impl TryFrom<String> for Base64 {
    type Error = LibError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        // Make sure the value is valid base64 string.
        Base64::decode(&value)?;
        Ok(Self(value))
    }
}

impl Base64 {
    /// Decodes this Base64 encoding to bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, LibError> {
        Self::decode(&self.0)
    }
    /// Encodes bytes as a Base64.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Self::encode(bytes))
    }
    /// Get a string representation of this Base64 encoding.
    pub fn encoded(&self) -> String {
        self.0.clone()
    }
}

impl Encoding for Base64 {
    fn decode(s: &str) -> Result<Vec<u8>, LibError> {
        base64ct::Base64::decode_vec(s).map_err(|_e| anyhow!("Error decoding {s}"))
    }

    fn encode<T: AsRef<[u8]>>(data: T) -> String {
        base64ct::Base64::encode_string(data.as_ref())
    }
}

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
    fn sign(&self, msg: &[u8]) -> String {
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
    fn duplicate(&self) -> SuiKeyPair {
        match self {
            SuiKeyPair::Ed25519(kp) => {
                SuiKeyPair::Ed25519(Ed25519KeyPair::from_bytes(kp.as_bytes()).unwrap())
            }
            SuiKeyPair::Secp256k1(kp) => {
                SuiKeyPair::Secp256k1(Secp256k1KeyPair::from_bytes(kp.as_bytes()).unwrap())
            }
            SuiKeyPair::Secp256r1(kp) => {
                SuiKeyPair::Secp256r1(Secp256r1KeyPair::from_bytes(kp.as_bytes()).unwrap())
            }
        }
    }
}

/// Given a keystring, produce a keypair
fn keypair_from_keystring(keystring: String) -> Result<SuiKeyPair, LibError> {
    let b64b = &mut VecDeque::from(Base64::decode(&keystring).unwrap());
    let kscheme = SignatureScheme::from_flag_byte(&b64b.pop_front().unwrap()).unwrap();
    let rembytes = b64b.make_contiguous();
    match kscheme {
        SignatureScheme::ED25519 => Ok(SuiKeyPair::Ed25519(
            Ed25519KeyPair::from_bytes(rembytes).unwrap(),
        )),
        SignatureScheme::Secp256k1 => Ok(SuiKeyPair::Secp256k1(
            Secp256k1KeyPair::from_bytes(rembytes).unwrap(),
        )),
        SignatureScheme::Secp256r1 => Ok(SuiKeyPair::Secp256r1(
            Secp256r1KeyPair::from_bytes(rembytes).unwrap(),
        )),
        SignatureScheme::BLS12381
        | SignatureScheme::MultiSig
        | SignatureScheme::ZkLoginAuthenticator => Err(anyhow!(format!(
            "key derivation not supported {:?}",
            kscheme
        ))),
    }
}

pub fn validate_path(
    key_scheme: &SignatureScheme,
    path: Option<DerivationPath>,
) -> Result<DerivationPath, LibError> {
    match key_scheme {
        SignatureScheme::ED25519 => {
            match path.clone() {
                Some(p) => {
                    // The derivation path must be hardened at all levels with purpose = 44, coin_type = 784
                    if let &[purpose, coin_type, account, change, address] = p.as_ref() {
                        if Some(purpose)
                            == ChildNumber::new(DERVIATION_PATH_PURPOSE_ED25519, true).ok()
                            && Some(coin_type)
                                == ChildNumber::new(DERIVATION_PATH_COIN_TYPE, true).ok()
                            && account.is_hardened()
                            && change.is_hardened()
                            && address.is_hardened()
                        {
                            Ok(p)
                        } else {
                            Err(anyhow!(format!("Invalid derivation path{:?}", path)))
                        }
                    } else {
                        Err(anyhow!(format!("Invalid derivatyion path{:?}", path)))
                    }
                }
                None => Ok(format!(
                    "m/{DERVIATION_PATH_PURPOSE_ED25519}'/{DERIVATION_PATH_COIN_TYPE}'/0'/0'/0'"
                )
                .parse()
                .map_err(|_| anyhow!(format!("Can not parse derivation path{:?}", path)))?),
            }
        }
        SignatureScheme::Secp256k1 => {
            match path.clone() {
                Some(p) => {
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
                            Err(anyhow!(format!("Invalid derivation path{:?}", path)))
                        }
                    } else {
                        Err(anyhow!(format!("Invalid derivatyion path{:?}", path)))
                    }
                }
                None => Ok(format!(
                    "m/{DERVIATION_PATH_PURPOSE_SECP256K1}'/{DERIVATION_PATH_COIN_TYPE}'/0'/0/0"
                )
                .parse()
                .map_err(|_| anyhow!(format!("Can not parse derivation path{:?}", path)))?),
            }
        }
        SignatureScheme::Secp256r1 => {
            match path.clone() {
                Some(p) => {
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
                            Err(anyhow!(format!("Invalid derivation path{:?}", path)))
                        }
                    } else {
                        Err(anyhow!(format!("Invalid derivatyion path{:?}", path)))
                    }
                }
                None => Ok(format!(
                    "m/{DERVIATION_PATH_PURPOSE_SECP256R1}'/{DERIVATION_PATH_COIN_TYPE}'/0'/0/0"
                )
                .parse()
                .map_err(|_| anyhow!(format!("Can not parse derivation path{:?}", path)))?),
            }
        }
        SignatureScheme::BLS12381
        | SignatureScheme::MultiSig
        | SignatureScheme::ZkLoginAuthenticator => Err(anyhow! {
            format!("key derivation not supported {:?}", key_scheme),
        }),
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
    derivation_path: Option<String>,
    word_length: Option<String>,
) -> Result<(SignatureScheme, String, SuiKeyPair)> {
    let scheme = SignatureScheme::from_flag_byte(&scheme).unwrap();
    let dvpath = match derivation_path {
        Some(s) => Some(DerivationPath::from_str(&s).unwrap()),
        None => None,
    };
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

static GLOBAL_DATA: Mutex<BTreeMap<String, SuiKeyPair>> =
    Mutex::new(BTreeMap::<String, SuiKeyPair>::new());

/// Store a keypair associated to the hashed public key.
///
/// Throws error if key/token already exists
fn store_key(key_pair: SuiKeyPair) -> Result<(Vec<u8>, String), LibError> {
    // Hash the public key bytes
    let key_bytes = key_pair.pubkey().as_bytes();
    let mut hasher = DefaultHash::default();
    hasher.update(key_bytes.clone());
    // Stringify the token and use as key to keypair
    let mut map = GLOBAL_DATA.lock().unwrap();
    let token = Base64::encode(hasher.finalize().digest);
    if map.contains_key(&token) {
        return Err(anyhow!(format!("Failed to generate keypair: {:?}", token)));
    }
    map.insert(token.clone(), key_pair);
    Ok((key_bytes, token))
}

/// Get a duplicate of the keypair from token
fn keypair_from_token(token: &String) -> Result<SuiKeyPair, LibError> {
    let map = GLOBAL_DATA.lock().unwrap();
    if let Some(kp) = map.get(token) {
        return Ok(kp.duplicate());
    }
    Err(anyhow!(format!("Token {} not found", token)))
}

/// Returns a keystrings scheme, public key bytes and a token from a Sui keystring.
/// Assumes that the inbound keystring is valid (e.g. `flag | private_key bytes`)
#[pyfunction]
fn keys_from_keystring(in_str: String) -> (u8, Vec<u8>, String) {
    assert!(in_str.len() != 0, "Requires valid keystring");
    let kp = keypair_from_keystring(in_str).unwrap();
    let scheme = kp.scheme().flag();
    let (pub_key, token) = store_key(kp).unwrap();
    (scheme, pub_key, token)
}

/// Returns a new keystrings scheme, public key bytes and a token./// Assumes that the inbound keystring is valid (e.g. `flag | private_key bytes`)
#[pyfunction]
fn generate_new_keypair(
    in_scheme: u8,
    derv_path: Option<String>,
    word_count: Option<String>,
) -> (u8, String, Vec<u8>, String) {
    let (scheme, phrase, kp) = new_keypair(in_scheme, derv_path, word_count).unwrap();
    // Hash the public key
    let (pub_key, token) = store_key(kp).unwrap();
    (scheme.flag(), phrase, pub_key, token)
}

/// Signs a message with optional intent, otherwise default is used
/// The in_data string is the tx_bytes string
#[pyfunction]
fn sign_digest(token: String, in_data: String, intent: Option<Vec<u8>>) -> Vec<u8> {
    let kp = keypair_from_token(&token).unwrap();
    let intent_msg = match intent {
        Some(inv) => inv,
        None => vec![0, 0, 0],
    };
    let mut hasher = DefaultHash::default();
    hasher.update(intent_msg);
    hasher.update(Base64::decode(&in_data).unwrap());
    let digest = hasher.finalize().digest;
    let mut sig = Base64::decode(&kp.sign(&digest)).unwrap();
    sig.insert(0, kp.scheme().flag());
    sig.extend(kp.pubkey().as_bytes());
    sig
}

/// The pysui_fastcrypto module implemented in Rust.  In order
/// to import the function name must match the Cargo.toml name
#[pymodule]
fn pysui_fastcrypto(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(keys_from_keystring, m)?)?;
    m.add_function(wrap_pyfunction!(generate_new_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(sign_digest, m)?)?;

    Ok(())
}
