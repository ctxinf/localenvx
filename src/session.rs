//! Load the selected credential file once per session.
use crate::crypto::Key;
use anyhow::Result;

pub struct Session {
    key: Key,
}

impl Session {
    pub fn open() -> Result<Self> {
        let cfg = crate::config::load()?;
        Ok(Self {
            key: Key::from_base64(&cfg.key)?,
        })
    }

    pub fn key(&self) -> &Key {
        &self.key
    }
}
