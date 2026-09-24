//! 密钥派生与值级加解密。
//!
//! password ──argon2id(salt)──▶ key ──XChaCha20-Poly1305──▶ .env 里的值

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

pub const PREFIX: &str = "encrypted:v1:";
const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 16;

/// 派生出的对称密钥，drop 时擦除。
pub struct Key([u8; 32]);

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // m=64MB/t=3 在本机约 ~80ms，满足 <100ms 的启动开销目标。
        Self {
            m: 65536,
            t: 3,
            p: 4,
        }
    }
}

pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| anyhow!("获取随机数失败: {e}"))?;
    Ok(buf)
}

pub fn new_salt_b64() -> Result<String> {
    Ok(B64.encode(random_bytes(SALT_LEN)?))
}

pub fn derive_key(password: &str, salt_b64: &str, p: KdfParams) -> Result<Key> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let salt = B64
        .decode(salt_b64.trim())
        .context("config 里的 kdf.salt 不是合法 base64")?;
    if salt.len() < 8 {
        bail!("kdf.salt 太短（至少 8 字节）");
    }
    let params =
        Params::new(p.m, p.t, p.p, Some(32)).map_err(|e| anyhow!("argon2 参数非法: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| anyhow!("密钥派生失败: {e}"))?;
    Ok(Key(key))
}

pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(PREFIX)
}

/// AAD 绑定变量名，防止把 A 的密文剪贴到 B 上。
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
        .map_err(|_| anyhow!("加密失败"))?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    Ok(format!("{PREFIX}{}", B64URL.encode(&blob)))
}

pub fn decrypt(key: &Key, name: &str, value: &str) -> Result<Zeroizing<String>> {
    let body = value
        .strip_prefix(PREFIX)
        .ok_or_else(|| anyhow!("{name}: 不是 {PREFIX} 格式的密文"))?;
    let blob = B64URL
        .decode(body.trim())
        .with_context(|| format!("{name}: 密文 base64 解码失败"))?;
    if blob.len() <= NONCE_LEN + 16 {
        bail!("{name}: 密文长度非法");
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
        .map_err(|_| anyhow!("{name}: 解密失败（密码错误、密文损坏，或变量被改名）"))?;
    let s = String::from_utf8(pt).map_err(|e| {
        let mut bytes = e.into_bytes();
        bytes.zeroize();
        anyhow!("{name}: 解密结果不是合法 UTF-8")
    })?;
    Ok(Zeroizing::new(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        derive_key(
            "pw",
            &new_salt_b64().unwrap(),
            KdfParams { m: 8, t: 1, p: 1 },
        )
        .unwrap()
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
    fn wrong_password_fails() {
        let salt = new_salt_b64().unwrap();
        let p = KdfParams { m: 8, t: 1, p: 1 };
        let a = derive_key("pw", &salt, p).unwrap();
        let b = derive_key("nope", &salt, p).unwrap();
        let c = encrypt(&a, "K", "v").unwrap();
        assert!(decrypt(&b, "K", &c).is_err());
    }
}
