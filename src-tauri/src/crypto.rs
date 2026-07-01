use crate::error::{VaultError, VaultResult};
use crate::models::{AeadEnvelope, KdfProfile};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 16;
pub const DEFAULT_CHUNK_SIZE: usize = 16 * 1024 * 1024;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial {
    bytes: [u8; KEY_LEN],
}

impl KeyMaterial {
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

pub fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

pub fn b64_encode(bytes: impl AsRef<[u8]>) -> String {
    STANDARD.encode(bytes)
}

pub fn b64_decode(value: &str) -> VaultResult<Vec<u8>> {
    STANDARD.decode(value).map_err(VaultError::from)
}

pub fn blake3_b64(bytes: impl AsRef<[u8]>) -> String {
    b64_encode(blake3::hash(bytes.as_ref()).as_bytes())
}

pub fn random_key() -> KeyMaterial {
    let mut bytes = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut bytes);
    KeyMaterial::new(bytes)
}

pub fn random_salt_b64() -> String {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    b64_encode(salt)
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn default_kdf_profile() -> KdfProfile {
    KdfProfile {
        algorithm: "argon2id-v19".to_string(),
        #[cfg(not(test))]
        memory_cost_kib: 194_560,
        #[cfg(test)]
        memory_cost_kib: 4_096,
        #[cfg(not(test))]
        time_cost: 3,
        #[cfg(test)]
        time_cost: 1,
        #[cfg(not(test))]
        parallelism: 2,
        #[cfg(test)]
        parallelism: 1,
        salt_b64: random_salt_b64(),
    }
}

pub fn derive_key(passphrase: &SecretString, profile: &KdfProfile) -> VaultResult<KeyMaterial> {
    if profile.algorithm != "argon2id-v19" {
        return Err(VaultError::Crypto(format!(
            "unsupported KDF algorithm {}",
            profile.algorithm
        )));
    }

    let salt = b64_decode(&profile.salt_b64)?;
    let params = argon2::Params::new(
        profile.memory_cost_kib,
        profile.time_cost,
        profile.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|error| VaultError::Crypto(error.to_string()))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut output = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.expose_secret().as_bytes(), &salt, &mut output)
        .map_err(|error| VaultError::Crypto(error.to_string()))?;

    Ok(KeyMaterial::new(output))
}

pub fn encrypt_bytes(key: &KeyMaterial, aad: &[u8], plaintext: &[u8]) -> VaultResult<AeadEnvelope> {
    let cipher = Aes256Gcm::new_from_slice(key.expose())
        .map_err(|error| VaultError::Crypto(error.to_string()))?;
    let nonce = random_nonce();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|error| VaultError::Crypto(error.to_string()))?;

    Ok(AeadEnvelope {
        nonce_b64: b64_encode(nonce),
        ciphertext_b64: b64_encode(ciphertext),
    })
}

pub fn decrypt_bytes(
    key: &KeyMaterial,
    aad: &[u8],
    envelope: &AeadEnvelope,
) -> VaultResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.expose())
        .map_err(|error| VaultError::Crypto(error.to_string()))?;
    let nonce_bytes = b64_decode(&envelope.nonce_b64)?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(VaultError::Crypto(
            "invalid AES-GCM nonce length".to_string(),
        ));
    }
    let ciphertext = b64_decode(&envelope.ciphertext_b64)?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)
}

pub fn wrap_key(
    wrapping_key: &KeyMaterial,
    key_to_wrap: &KeyMaterial,
    aad_label: &str,
) -> VaultResult<AeadEnvelope> {
    encrypt_bytes(wrapping_key, aad_label.as_bytes(), key_to_wrap.expose())
}

pub fn unwrap_key(
    wrapping_key: &KeyMaterial,
    envelope: &AeadEnvelope,
    aad_label: &str,
) -> VaultResult<KeyMaterial> {
    let plaintext = decrypt_bytes(wrapping_key, aad_label.as_bytes(), envelope)?;
    if plaintext.len() != KEY_LEN {
        return Err(VaultError::Crypto(
            "wrapped key had invalid length".to_string(),
        ));
    }
    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(&plaintext);
    Ok(KeyMaterial::new(bytes))
}

pub fn encrypt_json<T: Serialize>(
    key: &KeyMaterial,
    aad_label: &str,
    value: &T,
) -> VaultResult<AeadEnvelope> {
    let serialized = serde_json::to_vec(value)?;
    encrypt_bytes(key, aad_label.as_bytes(), &serialized)
}

pub fn decrypt_json<T: DeserializeOwned>(
    key: &KeyMaterial,
    aad_label: &str,
    envelope: &AeadEnvelope,
) -> VaultResult<T> {
    let plaintext = decrypt_bytes(key, aad_label.as_bytes(), envelope)?;
    serde_json::from_slice(&plaintext).map_err(VaultError::from)
}

pub fn encrypt_chunk(
    file_key: &KeyMaterial,
    file_id: &str,
    index: u64,
    plaintext: &[u8],
) -> VaultResult<(String, Vec<u8>)> {
    let aad = format!("secure-vault:v1:file-chunk:{file_id}:{index}");
    let envelope = encrypt_bytes(file_key, aad.as_bytes(), plaintext)?;
    let ciphertext = b64_decode(&envelope.ciphertext_b64)?;
    Ok((envelope.nonce_b64, ciphertext))
}

pub fn decrypt_chunk(
    file_key: &KeyMaterial,
    file_id: &str,
    index: u64,
    nonce_b64: &str,
    ciphertext: &[u8],
) -> VaultResult<Vec<u8>> {
    let aad = format!("secure-vault:v1:file-chunk:{file_id}:{index}");
    let envelope = AeadEnvelope {
        nonce_b64: nonce_b64.to_string(),
        ciphertext_b64: b64_encode(ciphertext),
    };
    decrypt_bytes(file_key, aad.as_bytes(), &envelope)
}

pub fn decompress_chunk(input: &[u8]) -> VaultResult<Vec<u8>> {
    zstd::stream::decode_all(input).map_err(|error| VaultError::Crypto(error.to_string()))
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    left.ct_eq(right).into()
}
