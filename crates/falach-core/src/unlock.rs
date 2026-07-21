//! Internal adapter from Falach secret wrappers to `keepass-rs` keys.

use std::io::Cursor;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Keyfile, MasterPassword, VaultError};

#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub(crate) struct KeyfileMaterial(Option<Vec<u8>>);

impl KeyfileMaterial {
    pub(crate) fn from_keyfile(keyfile: Option<&Keyfile>) -> Result<Self, VaultError> {
        match keyfile {
            None => Ok(Self(None)),
            Some(Keyfile::Bytes(bytes)) => Ok(Self(Some(bytes.clone()))),
            Some(Keyfile::Path(path)) => {
                let bytes = std::fs::read(path).map_err(|source| VaultError::Io {
                    source,
                    path: path.clone(),
                })?;
                Ok(Self(Some(bytes)))
            }
        }
    }

    fn as_deref(&self) -> Option<&[u8]> {
        self.0.as_deref()
    }
}

pub(crate) fn build_database_key(
    master: &MasterPassword,
    keyfile: Option<&Keyfile>,
) -> Result<keepass::DatabaseKey, VaultError> {
    let material = KeyfileMaterial::from_keyfile(keyfile)?;
    build_database_key_from_material(master, &material)
}

pub(crate) fn build_database_key_from_material(
    master: &MasterPassword,
    material: &KeyfileMaterial,
) -> Result<keepass::DatabaseKey, VaultError> {
    let mut key = keepass::DatabaseKey::new().with_password(master.as_str());

    if let Some(bytes) = material.as_deref() {
        let mut reader = Cursor::new(bytes);
        key = key
            .with_keyfile(&mut reader)
            .map_err(|source| VaultError::Io {
                source,
                path: "<in-memory keyfile>".into(),
            })?;
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn build_password_only_key_succeeds() {
        let master = MasterPassword::new("correct horse battery staple".to_string());
        let key = build_database_key(&master, None).expect("password-only key");
        assert!(!key.is_empty());
    }

    #[test]
    fn build_with_keyfile_path_succeeds() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("keyfile.bin");
        std::fs::write(&path, b"keyfile bytes").expect("write keyfile");

        let master = MasterPassword::new("pw".to_string());
        let keyfile = Keyfile::Path(path);
        let key = build_database_key(&master, Some(&keyfile)).expect("path keyfile");
        assert!(!key.is_empty());
    }

    #[test]
    fn build_with_keyfile_bytes_succeeds() {
        let master = MasterPassword::new("pw".to_string());
        let keyfile = Keyfile::Bytes(b"keyfile bytes".to_vec());
        let key = build_database_key(&master, Some(&keyfile)).expect("bytes keyfile");
        assert!(!key.is_empty());
    }

    #[test]
    fn build_with_missing_keyfile_path_errors() {
        let master = MasterPassword::new("pw".to_string());
        let path = std::path::PathBuf::from("/definitely/not/a/falach/keyfile");
        let keyfile = Keyfile::Path(path.clone());

        let err = build_database_key(&master, Some(&keyfile)).expect_err("missing keyfile errors");
        assert!(matches!(err, VaultError::Io { path: ref p, .. } if p == &path));
    }
}
