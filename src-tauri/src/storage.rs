use crate::credentials::CredentialStore;
use crate::models::{AuthMethod, ServerDraft, ServerProfile};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone)]
pub struct Store {
    connection: Arc<Mutex<Connection>>,
    credentials: CredentialStore,
}

impl Store {
    pub fn open(path: &Path, credentials_path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("Could not create Serverbox data directory: {error}"))?;
        }
        let connection = Connection::open(path)
            .map_err(|error| format!("Could not open Serverbox database: {error}"))?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS servers (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    host TEXT NOT NULL,
                    username TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    auth_method TEXT NOT NULL,
                    key_path TEXT,
                    group_name TEXT,
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    favorite INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_connected_at TEXT,
                    jump_host_id TEXT REFERENCES servers(id) ON DELETE SET NULL
                 );
                 CREATE TABLE IF NOT EXISTS server_notes (
                    server_id TEXT PRIMARY KEY NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                    notes TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS saved_commands (
                    id TEXT PRIMARY KEY NOT NULL,
                    server_id TEXT REFERENCES servers(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    command TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS tunnels (
                    id TEXT PRIMARY KEY NOT NULL,
                    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    bind_host TEXT NOT NULL,
                    bind_port INTEGER NOT NULL,
                    target_host TEXT NOT NULL,
                    target_port INTEGER NOT NULL
                 );
                 INSERT INTO schema_version(version)
                 SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);",
            )
            .map_err(|error| format!("Could not initialize Serverbox database: {error}"))?;
        let has_jump_host = {
            let mut statement = connection
                .prepare("PRAGMA table_info(servers)")
                .map_err(|error| format!("Could not inspect Serverbox database: {error}"))?;
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|error| format!("Could not inspect Serverbox database: {error}"))?;
            columns
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|error| format!("Could not inspect Serverbox database: {error}"))?
                .iter()
                .any(|column| column == "jump_host_id")
        };
        if !has_jump_host {
            connection
                .execute(
                    "ALTER TABLE servers ADD COLUMN jump_host_id TEXT REFERENCES servers(id) ON DELETE SET NULL",
                    [],
                )
                .map_err(|error| format!("Could not add bastion support to Serverbox database: {error}"))?;
        }
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            credentials: CredentialStore::open(credentials_path)?,
        })
    }

    pub fn credential_status(&self) -> crate::models::CredentialStatus {
        self.credentials.status()
    }

    pub fn unlock_credentials(
        &self,
        password: &str,
    ) -> Result<crate::models::CredentialStatus, String> {
        self.credentials.unlock(password)
    }

    pub fn change_master_password(
        &self,
        current: &str,
        new: &str,
    ) -> Result<crate::models::CredentialStatus, String> {
        self.credentials.change_master_password(current, new)
    }

    pub fn reset_credentials(&self, password: &str) -> Result<(), String> {
        self.credentials.reset(password)
    }

    pub(crate) fn get_secret(&self, server_id: &str, slot: &str) -> Result<Option<String>, String> {
        self.credentials.get(server_id, slot)
    }

    pub fn list_servers(&self) -> Result<Vec<ServerProfile>, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Serverbox database lock was poisoned".to_string())?;
        let mut statement = connection
            .prepare(
                "SELECT id, name, host, username, port, auth_method, key_path, group_name,
                        tags_json, favorite, created_at, updated_at, last_connected_at,
                        jump_host_id,
                        COALESCE((SELECT notes FROM server_notes WHERE server_id = servers.id), '')
                 FROM servers ORDER BY favorite DESC, name COLLATE NOCASE ASC",
            )
            .map_err(|error| format!("Could not read servers: {error}"))?;
        let rows = statement
            .query_map([], row_to_server)
            .map_err(|error| format!("Could not read servers: {error}"))?;
        rows.map(|row| row.map_err(|error| format!("Could not decode server: {error}")))
            .collect()
    }

    pub fn get_server(&self, id: &str) -> Result<ServerProfile, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Serverbox database lock was poisoned".to_string())?;
        connection
            .query_row(
                "SELECT id, name, host, username, port, auth_method, key_path, group_name,
                        tags_json, favorite, created_at, updated_at, last_connected_at,
                        jump_host_id,
                        COALESCE((SELECT notes FROM server_notes WHERE server_id = servers.id), '')
                 FROM servers WHERE id = ?1",
                [id],
                row_to_server,
            )
            .optional()
            .map_err(|error| format!("Could not read server: {error}"))?
            .ok_or_else(|| "That server no longer exists".to_string())
    }

    pub fn save_server(&self, draft: &ServerDraft) -> Result<ServerProfile, String> {
        let name = required(&draft.name, "server name")?;
        let host = required(&draft.host, "host")?;
        let username = required(&draft.username, "username")?;
        if !(1..=u16::MAX as u32).contains(&draft.port) {
            return Err("Port must be between 1 and 65535".to_string());
        }
        let port = draft.port as u16;
        let now = Utc::now().to_rfc3339();
        let id = draft
            .id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let jump_host_id = draft
            .jump_host_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        self.validate_jump_host(&id, jump_host_id)?;
        let existing = self.get_server(&id).ok();
        let created_at = existing
            .as_ref()
            .map(|server| server.created_at.clone())
            .unwrap_or_else(|| now.clone());
        let tags: Vec<String> = draft
            .tags
            .iter()
            .map(|tag| tag.trim().trim_start_matches('#').to_lowercase())
            .filter(|tag| !tag.is_empty())
            .collect();
        let tags_json = serde_json::to_string(&tags).map_err(|error| error.to_string())?;
        if draft.notes.len() > 100_000 {
            return Err("Server notes are limited to 100 KB".to_string());
        }
        let auth_method = match draft.auth_method {
            AuthMethod::Password => "password",
            AuthMethod::PrivateKey => "privateKey",
        };
        let is_new = existing.is_none();
        let has_new_secret = [
            draft.password.as_deref(),
            draft.key_passphrase.as_deref(),
            draft.sudo_password.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|secret| !secret.is_empty());
        let updates_existing_credentials = !is_new
            && (draft.password.is_some()
                || draft.key_passphrase.is_some()
                || draft.sudo_password.is_some());
        let clears_possible_stale_credentials = is_new && draft.id.is_some();
        let updates_credentials =
            has_new_secret || updates_existing_credentials || clears_possible_stale_credentials;
        if updates_credentials {
            self.credentials.ensure_unlocked()?;
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Serverbox database lock was poisoned".to_string())?;
        connection
            .execute(
                "INSERT INTO servers
                    (id, name, host, username, port, auth_method, key_path, group_name,
                     tags_json, favorite, created_at, updated_at, last_connected_at, jump_host_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                 ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    host = excluded.host,
                    username = excluded.username,
                    port = excluded.port,
                    auth_method = excluded.auth_method,
                    key_path = excluded.key_path,
                    group_name = excluded.group_name,
                    tags_json = excluded.tags_json,
                    favorite = excluded.favorite,
                    jump_host_id = excluded.jump_host_id,
                    updated_at = excluded.updated_at",
                params![
                    id,
                    name,
                    host,
                    username,
                    port,
                    auth_method,
                    draft.key_path.as_deref(),
                    draft
                        .group_name
                        .as_deref()
                        .filter(|value| !value.trim().is_empty()),
                    tags_json,
                    draft.favorite,
                    created_at,
                    now,
                    existing
                        .as_ref()
                        .and_then(|server| server.last_connected_at.as_deref()),
                    jump_host_id,
                ],
            )
            .map_err(|error| format!("Could not save server: {error}"))?;
        connection
            .execute(
                "INSERT INTO server_notes(server_id, notes, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(server_id) DO UPDATE SET notes=excluded.notes, updated_at=excluded.updated_at",
                params![id, draft.notes, now],
            )
            .map_err(|error| format!("Could not save server notes: {error}"))?;
        drop(connection);

        if updates_credentials {
            self.credentials.update_server(
                &id,
                is_new,
                draft.password.as_deref(),
                draft.key_passphrase.as_deref(),
                draft.sudo_password.as_deref(),
            )?;
        }
        self.get_server(&id)
    }

    fn validate_jump_host(
        &self,
        server_id: &str,
        jump_host_id: Option<&str>,
    ) -> Result<(), String> {
        let Some(mut current_id) = jump_host_id.map(str::to_string) else {
            return Ok(());
        };
        let mut visited = std::collections::HashSet::new();
        visited.insert(server_id.to_string());
        loop {
            if !visited.insert(current_id.clone()) {
                return Err("Bastion profiles cannot contain a connection cycle".to_string());
            }
            let profile = self
                .get_server(&current_id)
                .map_err(|_| "The selected bastion profile no longer exists".to_string())?;
            let Some(next) = profile.jump_host_id else {
                return Ok(());
            };
            current_id = next;
        }
    }

    pub fn rename_server(&self, id: &str, name: &str) -> Result<ServerProfile, String> {
        let name = required(name, "server name")?;
        let now = Utc::now().to_rfc3339();
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Serverbox database lock was poisoned".to_string())?;
        let updated = connection
            .execute(
                "UPDATE servers SET name = ?1, updated_at = ?2 WHERE id = ?3",
                params![name, now, id],
            )
            .map_err(|error| format!("Could not rename server: {error}"))?;
        if updated == 0 {
            return Err("That server no longer exists".to_string());
        }
        drop(connection);
        self.get_server(id)
    }

    pub fn delete_server(&self, id: &str) -> Result<(), String> {
        self.credentials.remove_server(id)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Serverbox database lock was poisoned".to_string())?;
        connection
            .execute("DELETE FROM servers WHERE id = ?1", [id])
            .map_err(|error| format!("Could not delete server: {error}"))?;
        Ok(())
    }

    pub fn duplicate_server(&self, id: &str) -> Result<ServerProfile, String> {
        let source = self.get_server(id)?;
        let draft = ServerDraft {
            id: None,
            name: format!("{} copy", source.name),
            host: source.host,
            username: source.username,
            port: source.port.into(),
            auth_method: source.auth_method,
            key_path: source.key_path,
            jump_host_id: source.jump_host_id,
            group_name: source.group_name,
            tags: source.tags,
            notes: source.notes,
            favorite: false,
            password: self.get_secret(id, "password")?,
            key_passphrase: self.get_secret(id, "key-passphrase")?,
            sudo_password: self.get_secret(id, "sudo-password")?,
        };
        self.save_server(&draft)
    }

    pub fn mark_connected(&self, id: &str) -> Result<(), String> {
        let now = Utc::now().to_rfc3339();
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Serverbox database lock was poisoned".to_string())?;
        connection
            .execute(
                "UPDATE servers SET last_connected_at = ?1 WHERE id = ?2",
                params![now, id],
            )
            .map_err(|error| format!("Could not update connection history: {error}"))?;
        Ok(())
    }

    pub fn list_saved_commands(
        &self,
        server_id: Option<&str>,
    ) -> Result<Vec<crate::models::SavedCommand>, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Serverbox database lock was poisoned".to_string())?;
        let mut statement = connection.prepare(
            "SELECT id, server_id, name, command FROM saved_commands WHERE server_id IS NULL OR server_id = ?1 ORDER BY name COLLATE NOCASE"
        ).map_err(|error| format!("Could not read saved commands: {error}"))?;
        let rows = statement
            .query_map([server_id], |row| {
                Ok(crate::models::SavedCommand {
                    id: row.get(0)?,
                    server_id: row.get(1)?,
                    name: row.get(2)?,
                    command: row.get(3)?,
                })
            })
            .map_err(|error| format!("Could not read saved commands: {error}"))?;
        rows.map(|row| row.map_err(|error| format!("Could not decode saved command: {error}")))
            .collect()
    }

    pub fn save_saved_command(
        &self,
        input: &crate::models::SavedCommandInput,
    ) -> Result<crate::models::SavedCommand, String> {
        let name = required(&input.name, "command name")?;
        let command = required(&input.command, "command")?;
        if command.len() > 20_000 {
            return Err("Saved commands are limited to 20 KB".to_string());
        }
        if let Some(server_id) = input.server_id.as_deref() {
            self.get_server(server_id)?;
        }
        let id = input
            .id
            .clone()
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Serverbox database lock was poisoned".to_string())?;
        connection.execute(
            "INSERT INTO saved_commands(id, server_id, name, command) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(id) DO UPDATE SET server_id=excluded.server_id, name=excluded.name, command=excluded.command",
            params![id, input.server_id, name, command],
        ).map_err(|error| format!("Could not save command: {error}"))?;
        Ok(crate::models::SavedCommand {
            id,
            server_id: input.server_id.clone(),
            name,
            command,
        })
    }

    pub fn delete_saved_command(&self, id: &str) -> Result<(), String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Serverbox database lock was poisoned".to_string())?;
        connection
            .execute("DELETE FROM saved_commands WHERE id = ?1", [id])
            .map_err(|error| format!("Could not delete command: {error}"))?;
        Ok(())
    }

    pub fn list_tunnels(
        &self,
        server_id: &str,
    ) -> Result<Vec<crate::models::TunnelConfig>, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Serverbox database lock was poisoned".to_string())?;
        let mut statement = connection.prepare("SELECT id, server_id, name, kind, bind_host, bind_port, target_host, target_port FROM tunnels WHERE server_id=?1 ORDER BY name COLLATE NOCASE")
            .map_err(|error| format!("Could not read tunnels: {error}"))?;
        let rows = statement
            .query_map([server_id], |row| {
                Ok(crate::models::TunnelConfig {
                    id: row.get(0)?,
                    server_id: row.get(1)?,
                    name: row.get(2)?,
                    kind: row.get(3)?,
                    bind_host: row.get(4)?,
                    bind_port: row.get(5)?,
                    target_host: row.get(6)?,
                    target_port: row.get(7)?,
                })
            })
            .map_err(|error| format!("Could not read tunnels: {error}"))?;
        rows.map(|row| row.map_err(|error| format!("Could not decode tunnel: {error}")))
            .collect()
    }

    pub fn get_tunnel(&self, id: &str) -> Result<crate::models::TunnelConfig, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Serverbox database lock was poisoned".to_string())?;
        connection
            .query_row(
                "SELECT id, server_id, name, kind, bind_host, bind_port, target_host, target_port FROM tunnels WHERE id=?1",
                [id],
                |row| Ok(crate::models::TunnelConfig { id: row.get(0)?, server_id: row.get(1)?, name: row.get(2)?, kind: row.get(3)?, bind_host: row.get(4)?, bind_port: row.get(5)?, target_host: row.get(6)?, target_port: row.get(7)? }),
            )
            .optional()
            .map_err(|error| format!("Could not read tunnel: {error}"))?
            .ok_or_else(|| "That tunnel no longer exists".to_string())
    }

    pub fn save_tunnel(
        &self,
        input: &crate::models::TunnelInput,
    ) -> Result<crate::models::TunnelConfig, String> {
        self.get_server(&input.server_id)?;
        if !["local", "remote", "socks"].contains(&input.kind.as_str()) {
            return Err("Tunnel kind must be local, remote, or socks".to_string());
        }
        if !(1..=65535).contains(&input.bind_port) || !(1..=65535).contains(&input.target_port) {
            return Err("Tunnel ports must be between 1 and 65535".to_string());
        }
        let name = required(&input.name, "tunnel name")?;
        let bind_host = required(&input.bind_host, "bind host")?;
        let target_host = if input.kind == "socks" {
            input.target_host.trim().to_string()
        } else {
            required(&input.target_host, "target host")?
        };
        let id = input
            .id
            .clone()
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let tunnel = crate::models::TunnelConfig {
            id: id.clone(),
            server_id: input.server_id.clone(),
            name,
            kind: input.kind.clone(),
            bind_host,
            bind_port: input.bind_port as u16,
            target_host,
            target_port: input.target_port as u16,
        };
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Serverbox database lock was poisoned".to_string())?;
        connection.execute("INSERT INTO tunnels(id,server_id,name,kind,bind_host,bind_port,target_host,target_port) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO UPDATE SET name=excluded.name,kind=excluded.kind,bind_host=excluded.bind_host,bind_port=excluded.bind_port,target_host=excluded.target_host,target_port=excluded.target_port", params![tunnel.id,tunnel.server_id,tunnel.name,tunnel.kind,tunnel.bind_host,tunnel.bind_port,tunnel.target_host,tunnel.target_port])
            .map_err(|error| format!("Could not save tunnel: {error}"))?;
        Ok(tunnel)
    }

    pub fn delete_tunnel(&self, id: &str) -> Result<(), String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "Serverbox database lock was poisoned".to_string())?;
        connection
            .execute("DELETE FROM tunnels WHERE id=?1", [id])
            .map_err(|error| format!("Could not delete tunnel: {error}"))?;
        Ok(())
    }
}

fn required(value: &str, label: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("Enter a {label}"));
    }
    Ok(value.to_string())
}

fn row_to_server(row: &rusqlite::Row<'_>) -> rusqlite::Result<ServerProfile> {
    let auth_method: String = row.get(5)?;
    let tags_json: String = row.get(8)?;
    Ok(ServerProfile {
        id: row.get(0)?,
        name: row.get(1)?,
        host: row.get(2)?,
        username: row.get(3)?,
        port: row.get(4)?,
        auth_method: if auth_method == "privateKey" {
            AuthMethod::PrivateKey
        } else {
            AuthMethod::Password
        },
        key_path: row.get(6)?,
        group_name: row.get(7)?,
        tags: serde_json::from_str(&tags_json).unwrap_or_default(),
        jump_host_id: row.get(13)?,
        notes: row.get(14)?,
        favorite: row.get::<_, i64>(9)? != 0,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
        last_connected_at: row.get(12)?,
    })
}
