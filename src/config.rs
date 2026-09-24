//! ~/.config/localenvx/config.toml — salt, KDF parameters and (optionally) the password.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::crypto::KdfParams;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub kdf: Kdf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Kdf {
    pub algo: String,
    pub salt: String,
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl Drop for Config {
    fn drop(&mut self) {
        if let Some(p) = self.password.as_mut() {
            p.zeroize();
        }
    }
}

impl Config {
    pub fn new(salt: String, params: KdfParams, password: Option<String>) -> Self {
        Self {
            version: 1,
            password,
            kdf: Kdf {
                algo: "argon2id".into(),
                salt,
                m: params.m,
                t: params.t,
                p: params.p,
            },
        }
    }

    pub fn params(&self) -> KdfParams {
        KdfParams {
            m: self.kdf.m,
            t: self.kdf.t,
            p: self.kdf.p,
        }
    }
}

pub fn config_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("LOCALENVX_CONFIG_DIR") {
        return Ok(PathBuf::from(d));
    }
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => {
            let home = std::env::var_os("HOME").context("$HOME is not set")?;
            PathBuf::from(home).join(".config")
        }
    };
    Ok(base.join("localenvx"))
}

pub fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

pub fn load() -> Result<Config> {
    let path = config_path()?;
    if !path.exists() {
        bail!(
            "not initialized yet: run `localenvx init` first (config: {})",
            path.display()
        );
    }
    check_perms(&path)?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let cfg: Config =
        toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))?;
    if cfg.version != 1 {
        bail!(
            "unsupported config version {} (this binary only knows 1)",
            cfg.version
        );
    }
    if cfg.kdf.algo != "argon2id" {
        bail!("unsupported kdf.algo: {}", cfg.kdf.algo);
    }
    Ok(cfg)
}

pub fn save(cfg: &Config) -> Result<PathBuf> {
    let dir = config_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let path = dir.join("config.toml");
    let text = toml::to_string_pretty(cfg)?;
    write_private(&path, text.as_bytes())?;
    Ok(path)
}

/// Atomic write with mode 0600 (temp file then rename, so no half-written file is left).
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("toml.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path).with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}

/// Refuse to run if permissions are too broad (any bit set for group/other).
pub fn check_perms(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "{} has overly broad permissions ({:04o}); refusing to run. Run: chmod 600 {}",
                path.display(),
                mode,
                path.display()
            );
        }
    }
    let _ = path;
    Ok(())
}
