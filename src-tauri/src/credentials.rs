use crate::models::CredentialStatus;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

pub const MASTER_PASSWORD_REQUIRED: &str = "MASTER_PASSWORD_REQUIRED";
pub const MASTER_PASSWORD_SETUP_REQUIRED: &str = "MASTER_PASSWORD_SETUP_REQUIRED";
pub const MASTER_PASSWORD_INVALID: &str = "MASTER_PASSWORD_INVALID";
pub const MASTER_PASSWORD_NOT_CONFIGURED: &str = "MASTER_PASSWORD_NOT_CONFIGURED";

const FILE_MAGIC: &[u8] = b"SERVERBOX-CREDENTIALS";
const FILE_VERSION: u8 = 1;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const KEY_LENGTH: usize = 32;
const MIN_MASTER_PASSWORD_LENGTH: usize = 8;

#[derive(Clone)]
pub struct CredentialStore {
    inner: Arc<Mutex<CredentialState>>,
}

struct CredentialState {
    path: PathBuf,
    key: Option<Zeroizing<[u8; KEY_LENGTH]>>,
    salt: Option<[u8; SALT_LENGTH]>,
    document: CredentialDocument,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct CredentialDocument {
    #[serde(default)]
    servers: HashMap<String, ServerCredentials>,
}

/// A plaintext secret that is wiped from memory when its last reference is
/// dropped. Used for every stored password and passphrase in the vault.
#[derive(Clone, Default, Deserialize, Serialize)]
struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::ops::Deref for Secret {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct ServerCredentials {
    password: Option<Secret>,
    key_passphrase: Option<Secret>,
    sudo_password: Option<Secret>,
}

impl CredentialStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("Could not create credential vault directory: {error}"))?;
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(CredentialState {
                path: path.to_path_buf(),
                key: None,
                salt: None,
                document: CredentialDocument::default(),
            })),
        })
    }

    pub fn status(&self) -> CredentialStatus {
        let Ok(state) = self.inner.lock() else {
            return CredentialStatus {
                configured: self.path_exists(),
                unlocked: false,
            };
        };
        CredentialStatus {
            configured: state.path.exists(),
            unlocked: state.key.is_some(),
        }
    }

    pub fn ensure_unlocked(&self) -> Result<(), String> {
        let state = self
            .inner
            .lock()
            .map_err(|_| "Credential vault lock was poisoned".to_string())?;
        if state.key.is_some() {
            Ok(())
        } else if state.path.exists() {
            Err(format!(
                "{MASTER_PASSWORD_REQUIRED}: Unlock the credential vault to continue."
            ))
        } else {
            Err(format!(
                "{MASTER_PASSWORD_SETUP_REQUIRED}: Create a master password to protect saved credentials."
            ))
        }
    }

    pub fn unlock(&self, password: &str) -> Result<CredentialStatus, String> {
        validate_password(password)?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| "Credential vault lock was poisoned".to_string())?;
        if state.path.exists() {
            let (salt, document) = decrypt_file(&state.path, password)?;
            let key = derive_key(password, &salt)?;
            state.salt = Some(salt);
            state.key = Some(key);
            state.document = document;
        } else {
            let mut salt = [0u8; SALT_LENGTH];
            OsRng.fill_bytes(&mut salt);
            state.salt = Some(salt);
            state.key = Some(derive_key(password, &salt)?);
            state.document = CredentialDocument::default();
        }
        Ok(CredentialStatus {
            configured: state.path.exists(),
            unlocked: true,
        })
    }

    pub fn get(&self, server_id: &str, slot: &str) -> Result<Option<String>, String> {
        let state = self
            .inner
            .lock()
            .map_err(|_| "Credential vault lock was poisoned".to_string())?;
        if state.key.is_none() {
            if !state.path.exists() {
                return Ok(None);
            }
            return Err(format!(
                "{MASTER_PASSWORD_REQUIRED}: Unlock the credential vault to continue."
            ));
        }
        let Some(credentials) = state.document.servers.get(server_id) else {
            return Ok(None);
        };
        let value = match slot {
            "password" => credentials.password.as_deref(),
            "key-passphrase" => credentials.key_passphrase.as_deref(),
            "sudo-password" => credentials.sudo_password.as_deref(),
            _ => return Err("Unknown credential type".to_string()),
        };
        Ok(value.filter(|value| !value.is_empty()).map(str::to_string))
    }

    pub fn update_server(
        &self,
        server_id: &str,
        is_new: bool,
        password: Option<&str>,
        key_passphrase: Option<&str>,
        sudo_password: Option<&str>,
    ) -> Result<(), String> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| "Credential vault lock was poisoned".to_string())?;
        ensure_unlocked_state(&state)?;
        let previous = state.document.clone();
        let credentials = state
            .document
            .servers
            .entry(server_id.to_string())
            .or_default();
        if is_new || password.is_some() {
            credentials.password = normalize_secret(password);
        }
        if is_new || key_passphrase.is_some() {
            credentials.key_passphrase = normalize_secret(key_passphrase);
        }
        if is_new || sudo_password.is_some() {
            credentials.sudo_password = normalize_secret(sudo_password);
        }
        remove_empty_server(&mut state.document, server_id);
        if let Err(error) = persist_state(&state) {
            state.document = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn remove_server(&self, server_id: &str) -> Result<(), String> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| "Credential vault lock was poisoned".to_string())?;
        if !state.path.exists() {
            state.document.servers.remove(server_id);
            return Ok(());
        }
        ensure_unlocked_state(&state)?;
        let previous = state.document.clone();
        state.document.servers.remove(server_id);
        if let Err(error) = persist_state(&state) {
            state.document = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn change_master_password(
        &self,
        current: &str,
        new: &str,
    ) -> Result<CredentialStatus, String> {
        validate_password(current)?;
        validate_password(new)?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| "Credential vault lock was poisoned".to_string())?;
        if !state.path.exists() {
            return Err(format!(
                "{MASTER_PASSWORD_NOT_CONFIGURED}: There is no saved credential vault to change."
            ));
        }
        let (_, document) = decrypt_file(&state.path, current)?;
        let mut salt = [0u8; SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(new, &salt)?;
        persist_document(&state.path, &key, &salt, &document)?;
        state.key = Some(key);
        state.salt = Some(salt);
        state.document = document;
        Ok(CredentialStatus {
            configured: true,
            unlocked: true,
        })
    }

    pub fn reset(&self, password: &str) -> Result<(), String> {
        validate_password(password)?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| "Credential vault lock was poisoned".to_string())?;
        if !state.path.exists() {
            state.key = None;
            state.salt = None;
            state.document = CredentialDocument::default();
            return Ok(());
        }
        let _ = decrypt_file(&state.path, password)?;
        fs::remove_file(&state.path)
            .map_err(|error| format!("Could not reset the encrypted credential vault: {error}"))?;
        state.key = None;
        state.salt = None;
        state.document = CredentialDocument::default();
        Ok(())
    }

    fn path_exists(&self) -> bool {
        self.inner
            .lock()
            .map(|state| state.path.exists())
            .unwrap_or(false)
    }
}

fn ensure_unlocked_state(state: &CredentialState) -> Result<(), String> {
    if state.key.is_some() {
        Ok(())
    } else if state.path.exists() {
        Err(format!(
            "{MASTER_PASSWORD_REQUIRED}: Unlock the credential vault to continue."
        ))
    } else {
        Err(format!("{MASTER_PASSWORD_SETUP_REQUIRED}: Create a master password to protect saved credentials."))
    }
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_MASTER_PASSWORD_LENGTH {
        return Err(format!(
            "A master password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters long."
        ));
    }
    Ok(())
}

fn normalize_secret(value: Option<&str>) -> Option<Secret> {
    value
        .filter(|value| !value.is_empty())
        .map(|value| Secret(value.to_string()))
}

fn remove_empty_server(document: &mut CredentialDocument, server_id: &str) {
    let remove = document.servers.get(server_id).is_some_and(|credentials| {
        credentials.password.is_none()
            && credentials.key_passphrase.is_none()
            && credentials.sudo_password.is_none()
    });
    if remove {
        document.servers.remove(server_id);
    }
}

fn derive_key(
    password: &str,
    salt: &[u8; SALT_LENGTH],
) -> Result<Zeroizing<[u8; KEY_LENGTH]>, String> {
    let params = Params::new(64 * 1024, 3, 1, Some(KEY_LENGTH))
        .map_err(|error| format!("Could not configure the credential key derivation: {error}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    argon
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|error| format!("Could not derive the credential encryption key: {error}"))?;
    Ok(key)
}

fn decrypt_file(
    path: &Path,
    password: &str,
) -> Result<([u8; SALT_LENGTH], CredentialDocument), String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("Could not read the encrypted credential vault: {error}"))?;
    let (salt, nonce, ciphertext) = parse_file(&bytes)?;
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&*key)
        .map_err(|_| "Could not initialize credential encryption".to_string())?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|_| format!("{MASTER_PASSWORD_INVALID}: The master password is incorrect or the credential vault is damaged."))?,
    );
    let document = serde_json::from_slice(&plaintext)
        .map_err(|_| "The encrypted credential vault could not be decoded.".to_string())?;
    Ok((salt, document))
}

fn parse_file(bytes: &[u8]) -> Result<([u8; SALT_LENGTH], [u8; NONCE_LENGTH], &[u8]), String> {
    let header_length = FILE_MAGIC.len() + 1 + SALT_LENGTH + NONCE_LENGTH;
    if bytes.len() <= header_length || &bytes[..FILE_MAGIC.len()] != FILE_MAGIC {
        return Err("The encrypted credential vault has an unsupported format.".to_string());
    }
    let version_index = FILE_MAGIC.len();
    if bytes[version_index] != FILE_VERSION {
        return Err("The encrypted credential vault has an unsupported version.".to_string());
    }
    let salt_start = version_index + 1;
    let nonce_start = salt_start + SALT_LENGTH;
    let mut salt = [0u8; SALT_LENGTH];
    let mut nonce = [0u8; NONCE_LENGTH];
    salt.copy_from_slice(&bytes[salt_start..nonce_start]);
    nonce.copy_from_slice(&bytes[nonce_start..header_length]);
    Ok((salt, nonce, &bytes[header_length..]))
}

fn persist_state(state: &CredentialState) -> Result<(), String> {
    let key = state
        .key
        .as_ref()
        .ok_or_else(|| "The credential vault is locked".to_string())?;
    let salt = state
        .salt
        .as_ref()
        .ok_or_else(|| "The credential vault has no encryption salt".to_string())?;
    persist_document(&state.path, key, salt, &state.document)
}

fn persist_document(
    path: &Path,
    key: &[u8; KEY_LENGTH],
    salt: &[u8; SALT_LENGTH],
    document: &CredentialDocument,
) -> Result<(), String> {
    let plaintext =
        Zeroizing::new(serde_json::to_vec(document).map_err(|error| {
            format!("Could not encode the encrypted credential vault: {error}")
        })?);
    let mut nonce = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Could not initialize credential encryption".to_string())?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| "Could not encrypt the credential vault".to_string())?;
    let mut bytes =
        Vec::with_capacity(FILE_MAGIC.len() + 1 + SALT_LENGTH + NONCE_LENGTH + ciphertext.len());
    bytes.extend_from_slice(FILE_MAGIC);
    bytes.push(FILE_VERSION);
    bytes.extend_from_slice(salt);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    atomic_write(path, &bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("credentials");
    let temporary_path = path.with_file_name(format!(".{file_name}.{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary_path)
            .map_err(|error| format!("Could not create the encrypted credential vault: {error}"))?;
        file.write_all(bytes)
            .map_err(|error| format!("Could not write the encrypted credential vault: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("Could not flush the encrypted credential vault: {error}"))?;
        drop(file);
        #[cfg(windows)]
        if path.exists() {
            fs::remove_file(path).map_err(|error| {
                format!("Could not replace the encrypted credential vault: {error}")
            })?;
        }
        fs::rename(&temporary_path, path).map_err(|error| {
            format!("Could not finalize the encrypted credential vault: {error}")
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}
