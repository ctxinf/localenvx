//! 密码来源解析 + 惰性密钥派生。
//!
//! 优先级：--password-stdin / 交互输入 > LOCALENVX_PASSWORD > config.password > 交互提示。
//! 刻意不提供 `--password <值>`：避免进 shell history 与 /proc/*/cmdline。

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

    /// 派生一次，整个进程复用（`run` 的启动开销只付一次 argon2）。
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
        prompt_password("localenvx 密码: ")
    }
}

pub fn read_password_stdin() -> Result<Zeroizing<String>> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("从 stdin 读取密码失败")?;
    let pw = Zeroizing::new(buf.trim_end_matches(['\n', '\r']).to_string());
    if pw.is_empty() {
        bail!("stdin 上没有读到密码");
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
        bail!("需要密码但 stdin 不是终端；请设置 LOCALENVX_PASSWORD 或使用 --password-stdin");
    }
    let pw = Zeroizing::new(rpassword::prompt_password(prompt).context("读取密码失败")?);
    if pw.is_empty() {
        bail!("密码不能为空");
    }
    Ok(pw)
}

pub fn prompt_new_password() -> Result<Zeroizing<String>> {
    let a = prompt_password("设置密码: ")?;
    let b = prompt_password("再输一次: ")?;
    if *a != *b {
        bail!("两次输入不一致");
    }
    Ok(a)
}
