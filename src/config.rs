//! User and project credentials: a random encryption key.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::crypto::Key;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub key: String,
}

impl Drop for Config {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Config {
    pub fn new() -> Result<Self> {
        Ok(Self {
            version: 2,
            key: Key::generate()?.to_base64(),
        })
    }
}

pub fn config_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("LOCALENVX_CONFIG_DIR") {
        return Ok(PathBuf::from(d));
    }
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => default_config_base()?,
    };
    Ok(base.join("localenvx"))
}

fn default_config_base() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let appdata =
            std::env::var_os("APPDATA").context("APPDATA is not set; set LOCALENVX_CONFIG_DIR")?;
        Ok(PathBuf::from(appdata))
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var_os("HOME").context("HOME is not set; set LOCALENVX_CONFIG_DIR")?;
        Ok(PathBuf::from(home).join(".config"))
    }
}

thread_local! {
    static SELECTED_PATH: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

pub fn select_path(path: Option<PathBuf>) {
    SELECTED_PATH.with(|selected| *selected.borrow_mut() = path);
}

pub fn config_path() -> Result<PathBuf> {
    if let Some(path) = SELECTED_PATH.with(|selected| selected.borrow().clone()) {
        return Ok(path);
    }
    resolve_path(
        &config_dir()?.join("config.toml"),
        &std::env::current_dir()?,
    )
}

/// Resolve whole credential files from the nearest project or the user directory.
fn resolve_path(user: &Path, cwd: &Path) -> Result<PathBuf> {
    for dir in cwd.ancestors() {
        let project = dir.join(".localenvx/config.toml");
        if project.try_exists()? {
            return Ok(project);
        }
    }
    Ok(user.to_path_buf())
}

pub fn load() -> Result<Config> {
    let path = config_path()?;
    if !path.exists() {
        bail!(
            "not initialized yet: run `localenvx manage init` first (config: {})",
            path.display()
        );
    }
    check_perms(&path)?;
    let text = zeroize::Zeroizing::new(
        std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?,
    );
    // Inspect the version before parsing the new schema. Never print credential contents.
    #[derive(Deserialize)]
    struct Header {
        version: u32,
    }
    let header: Header = toml::from_str(&text).map_err(|_| {
        anyhow::anyhow!(
            "failed to parse {}: invalid credential file",
            path.display()
        )
    })?;
    if header.version == 1 {
        bail!(
            "legacy password-based credential file: {}; use the previous release with the original credentials to decrypt existing files before initializing a new key file (no files changed)",
            path.display()
        );
    }
    if header.version != 2 {
        bail!("unsupported config version {} (expected 2)", header.version);
    }
    let cfg: Config = toml::from_str(&text).map_err(|_| {
        anyhow::anyhow!(
            "failed to parse {}: invalid credential file",
            path.display()
        )
    })?;
    Key::from_base64(&cfg.key)?;
    Ok(cfg)
}

pub fn save(cfg: &Config) -> Result<PathBuf> {
    let path = config_path()?;
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
    }
    let text = zeroize::Zeroizing::new(toml::to_string_pretty(cfg)?);
    write_private(&path, text.as_bytes())?;
    Ok(path)
}

/// Create credentials without ever replacing an existing key file.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| {
        format!(
            "failed to create {} (existing credentials are never overwritten)",
            path.display()
        )
    })?;
    if let Err(error) = f.write_all(bytes).and_then(|_| f.sync_all()) {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(error).with_context(|| format!("failed to write {}", path.display()));
    }
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
