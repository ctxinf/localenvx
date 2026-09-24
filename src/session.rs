//! Password source resolution plus lazy key derivation.
//!
//! Precedence: --password-stdin / interactive input > LOCALENVX_PASSWORD > config.password > prompt.
//! `--password <value>` is deliberately not offered: it would land in shell history and /proc/*/cmdline.

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::crypto::{self, Key};

pub struct Session {
    pub cfg: Config,
    password_stdin: bool,
    key: Option<Key>,
}

impl Session {
    pub fn new(cfg: Config, password_stdin: bool) -> Self {
        Self {
            cfg,
            password_stdin,
            key: None,
        }
    }

    pub fn open(password_stdin: bool) -> Result<Self> {
        Ok(Self::new(crate::config::load()?, password_stdin))
    }

    /// Derive once and reuse for the whole process (`run` pays for argon2 only once).
    pub fn key(&mut self) -> Result<&Key> {
        if self.key.is_none() {
            let pw = self.password()?;
            let key = crypto::derive_key(&pw, &self.cfg.kdf.salt, self.cfg.params())?;
            self.key = Some(key);
        }
        Ok(self.key.as_ref().unwrap())
    }

    fn password(&self) -> Result<Zeroizing<String>> {
        if self.password_stdin {
            return read_password_stdin();
        }
        if let Ok(v) = std::env::var("LOCALENVX_PASSWORD") {
            if !v.is_empty() {
                return Ok(Zeroizing::new(v));
            }
        }
        if let Some(p) = self.cfg.password.as_deref() {
            if !p.is_empty() {
                return Ok(Zeroizing::new(p.to_string()));
            }
        }
        prompt_password("localenvx password: ")
    }
}

pub fn read_password_stdin() -> Result<Zeroizing<String>> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("failed to read the password from stdin")?;
    let pw = Zeroizing::new(buf.trim_end_matches(['\n', '\r']).to_string());
    if pw.is_empty() {
        bail!("no password received on stdin");
    }
    Ok(pw)
}

pub fn is_tty() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::isatty(libc::STDIN_FILENO) == 1
    }
    #[cfg(not(unix))]
    true
}

pub fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    if !is_tty() {
        bail!(
            "a password is required but stdin is not a terminal; set LOCALENVX_PASSWORD or use --password-stdin"
        );
    }
    let pw =
        Zeroizing::new(rpassword::prompt_password(prompt).context("failed to read the password")?);
    if pw.is_empty() {
        bail!("the password must not be empty");
    }
    Ok(pw)
}

pub fn prompt_new_password() -> Result<Zeroizing<String>> {
    let a = prompt_password("new password: ")?;
    let b = prompt_password("repeat password: ")?;
    if *a != *b {
        bail!("the two entries do not match");
    }
    Ok(a)
}
