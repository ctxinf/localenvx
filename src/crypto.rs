//! Random file credentials and value-level encryption.

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

pub const PREFIX: &str = "encrypted:v1:";
const NONCE_LEN: usize = 24;

/// The symmetric key, wiped on drop.
pub struct Key([u8; 32]);

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Key {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| anyhow!("failed to get random bytes: {e}"))?;
        Ok(Self(bytes))
    }

    pub fn from_base64(encoded: &str) -> Result<Self> {
        let bytes = Zeroizing::new(
            B64.decode(encoded)
                .map_err(|_| anyhow!("credential key is not valid base64"))?,
        );
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("credential key must contain exactly 32 bytes"))?;
        Ok(Self(key))
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }
}

pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| anyhow!("failed to get random bytes: {e}"))?;
    Ok(buf)
}

pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(PREFIX)
}

/// The AAD binds the variable name, so A's ciphertext cannot be pasted onto B.
pub fn encrypt(key: &Key, name: &str, plaintext: &str) -> Result<String> {
    let cipher = XChaCha20Poly1305::new(key.0.as_ref().into());
    let nonce_bytes = random_bytes(NONCE_LEN)?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: name.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    Ok(format!("{PREFIX}{}", B64URL.encode(&blob)))
}

pub fn decrypt(key: &Key, name: &str, value: &str) -> Result<Zeroizing<String>> {
    let body = value
        .strip_prefix(PREFIX)
        .ok_or_else(|| anyhow!("{name}: not a {PREFIX} ciphertext"))?;
    let blob = B64URL
        .decode(body.trim())
        .with_context(|| format!("{name}: failed to base64-decode the ciphertext"))?;
    if blob.len() < NONCE_LEN + 16 {
        bail!("{name}: invalid ciphertext length");
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.0.as_ref().into());
    let pt = cipher
        .decrypt(
            XNonce::from_slice(nonce_bytes),
            Payload {
                msg: ct,
                aad: name.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("{name}: decryption failed (wrong credential file, corrupted ciphertext, or the variable was renamed)"))?;
    let s = String::from_utf8(pt).map_err(|e| {
        let mut bytes = e.into_bytes();
        bytes.zeroize();
        anyhow!("{name}: decrypted output is not valid UTF-8")
    })?;
    Ok(Zeroizing::new(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        Key::generate().unwrap()
    }

    #[test]
    fn roundtrip() {
        let k = key();
        let c = encrypt(&k, "DATABASE_URL", "postgres://x").unwrap();
        assert!(is_encrypted(&c));
        assert_eq!(&*decrypt(&k, "DATABASE_URL", &c).unwrap(), "postgres://x");
    }

    #[test]
    fn aad_binds_name() {
        let k = key();
        let c = encrypt(&k, "DATABASE_URL", "secret").unwrap();
        assert!(decrypt(&k, "LOG_LEVEL", &c).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let a = key();
        let b = key();
        let c = encrypt(&a, "K", "v").unwrap();
        assert!(decrypt(&b, "K", &c).is_err());
    }

    #[test]
    fn credential_roundtrip_and_validation() {
        let a = key();
        let b = Key::from_base64(&a.to_base64()).unwrap();
        let c = encrypt(&a, "K", "v").unwrap();
        assert_eq!(&*decrypt(&b, "K", &c).unwrap(), "v");
        for input in ["", "invalid", "c2hvcnQ="] {
            assert!(Key::from_base64(input).is_err());
        }
    }
}
