use crate::models::{AuthMethod, ServerCapabilities, ServerProfile};
use crate::storage::Store;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde_json::json;
use sha2::{Digest, Sha256};
use ssh2::{Channel, CheckResult, ErrorCode, KnownHostFileKind, Session, Sftp};
use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, OnceLock, TryLockError,
};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
const CONNECTION_PROBE_TIMEOUT: Duration = Duration::from_secs(8);
pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(35);
/// Idle timeout for legitimately long operations such as Compose rebuilds,
/// image pulls, and package upgrades. Cancellation still applies.
pub(crate) const LONG_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
/// Output cap applied when a caller does not pass an explicit limit so no
/// command can grow its buffers without bound.
pub(crate) const DEFAULT_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
pub(crate) const MAX_LOG_OUTPUT_BYTES: usize = 1024 * 1024;
pub(crate) const KEEPALIVE_INTERVAL_SECONDS: u32 = 15;
const PENDING_CANCELLATION_TTL: Duration = Duration::from_secs(60);
const MAX_PENDING_CANCELLATIONS: usize = 1_024;
pub const OPERATION_CANCELLED: &str = "Operation cancelled";

struct CachedClient {
    profile_key: String,
    client: Arc<Mutex<SshClient>>,
}

struct OperationState {
    cancelled: Arc<AtomicBool>,
    pending_since: Option<Instant>,
}

pub(crate) struct OperationHandle {
    id: String,
    cancelled: Arc<AtomicBool>,
}

impl OperationHandle {
    pub(crate) fn cancellation(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }
}

static CONNECTIONS: OnceLock<Mutex<HashMap<String, CachedClient>>> = OnceLock::new();
static OPERATIONS: OnceLock<Mutex<HashMap<String, OperationState>>> = OnceLock::new();

fn connections() -> &'static Mutex<HashMap<String, CachedClient>> {
    CONNECTIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn operations() -> &'static Mutex<HashMap<String, OperationState>> {
    OPERATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

pub struct SshClient {
    session: Session,
    cancellation: Option<Arc<AtomicBool>>,
    capabilities: Option<ServerCapabilities>,
    container_runtime: Option<String>,
}

impl SshClient {
    pub(crate) fn connect_with_cancellation(
        profile: &ServerProfile,
        cancellation: Option<&Arc<AtomicBool>>,
        store: &Store,
    ) -> Result<Self, String> {
        let mut visited = Vec::new();
        Self::connect_profile(profile, cancellation, store, &mut visited)
    }

    fn connect_profile(
        profile: &ServerProfile,
        cancellation: Option<&Arc<AtomicBool>>,
        store: &Store,
        visited: &mut Vec<String>,
    ) -> Result<Self, String> {
        if visited.iter().any(|id| id == &profile.id) {
            return Err("Bastion profiles contain a connection cycle".to_string());
        }
        if visited.len() >= 16 {
            return Err("Bastion chains are limited to 16 profiles".to_string());
        }
        visited.push(profile.id.clone());
        let session = open_session(profile, cancellation, store, visited)?;
        verify_host_key(&session, profile)?;
        authenticate(&session, profile, store)?;
        session.set_keepalive(true, KEEPALIVE_INTERVAL_SECONDS);
        ensure_not_cancelled(cancellation)?;
        visited.pop();
        Ok(Self {
            session,
            cancellation: None,
            capabilities: None,
            container_runtime: None,
        })
    }

    fn set_cancellation(&mut self, cancellation: Option<Arc<AtomicBool>>) {
        self.cancellation = cancellation;
    }

    fn clear_cancellation(&mut self) {
        self.cancellation = None;
    }

    pub fn check_cancelled(&self) -> Result<(), String> {
        ensure_not_cancelled(self.cancellation.as_ref())
    }

    pub(crate) fn cancellation_token(&self) -> Option<Arc<AtomicBool>> {
        self.cancellation.clone()
    }

    pub(crate) fn remember_capabilities(&mut self, capabilities: ServerCapabilities) {
        self.capabilities = Some(capabilities);
    }

    pub(crate) fn container_runtime(&self) -> Option<&str> {
        self.container_runtime.as_deref()
    }

    pub(crate) fn remember_container_runtime(&mut self, runtime: String) {
        self.container_runtime = Some(runtime);
    }

    fn connection_is_usable(&mut self) -> bool {
        if !self.session.authenticated() {
            return false;
        }
        match self.session.keepalive_send() {
            Ok(_) => true,
            Err(error) if error.code() == ErrorCode::Session(-37) => true,
            Err(_) => false,
        }
    }

    pub fn exec(&mut self, command: &str) -> Result<ExecOutput, String> {
        self.exec_with_input(command, None)
    }

    /// Like `exec`, but tolerant of long silent stretches (builds, pulls,
    /// package operations). Cancellation still interrupts it immediately.
    pub(crate) fn exec_long(&mut self, command: &str) -> Result<ExecOutput, String> {
        self.exec_with_input_limited_timeout(command, None, None, LONG_COMMAND_TIMEOUT)
    }

    pub fn exec_with_input(
        &mut self,
        command: &str,
        input: Option<&[u8]>,
    ) -> Result<ExecOutput, String> {
        self.exec_with_input_limited(command, input, None)
    }

    pub(crate) fn exec_posix_script_bounded(
        &mut self,
        script: &str,
        arguments: &[&str],
        max_output_bytes: usize,
    ) -> Result<String, String> {
        self.exec_posix_script_bounded_with_timeout(
            script,
            arguments,
            max_output_bytes,
            COMMAND_TIMEOUT,
        )
    }

    pub(crate) fn exec_posix_script_bounded_with_timeout(
        &mut self,
        script: &str,
        arguments: &[&str],
        max_output_bytes: usize,
        idle_timeout: Duration,
    ) -> Result<String, String> {
        let command = posix_script_command("LC_ALL=C sh -s", arguments);
        execute_posix_script_bounded(
            self,
            &command,
            script.as_bytes(),
            max_output_bytes,
            idle_timeout,
        )
    }

    pub(crate) fn exec_bounded(
        &mut self,
        command: &str,
        max_output_bytes: usize,
    ) -> Result<ExecOutput, String> {
        self.exec_with_input_limited(command, None, Some(max_output_bytes.saturating_add(1)))
    }

    pub(crate) fn exec_bounded_with_timeout(
        &mut self,
        command: &str,
        max_output_bytes: usize,
        idle_timeout: Duration,
    ) -> Result<ExecOutput, String> {
        self.exec_with_input_limited_timeout(
            command,
            None,
            Some(max_output_bytes.saturating_add(1)),
            idle_timeout,
        )
    }

    fn exec_with_input_limited(
        &mut self,
        command: &str,
        input: Option<&[u8]>,
        output_limit: Option<usize>,
    ) -> Result<ExecOutput, String> {
        self.exec_with_input_limited_timeout(command, input, output_limit, COMMAND_TIMEOUT)
    }

    fn exec_with_input_limited_timeout(
        &mut self,
        command: &str,
        input: Option<&[u8]>,
        output_limit: Option<usize>,
        idle_timeout: Duration,
    ) -> Result<ExecOutput, String> {
        self.check_cancelled()?;
        // The output bound is mandatory: callers that do not pass an explicit
        // limit still get the default cap so a misbehaving host cannot grow
        // these buffers without end.
        let output_limit = Some(output_limit.unwrap_or(DEFAULT_OUTPUT_LIMIT));
        let mut channel = self
            .session
            .channel_session()
            .map_err(|error| format!("Could not open SSH command channel: {error}"))?;
        channel
            .exec(command)
            .map_err(|error| format!("Could not execute remote command: {error}"))?;
        if let Some(input) = input {
            self.check_cancelled()?;
            channel
                .write_all(input)
                .map_err(|error| format!("Could not send command input: {error}"))?;
            channel
                .send_eof()
                .map_err(|error| format!("Could not finish command input: {error}"))?;
        }
        self.check_cancelled()?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut stderr_channel = channel.stderr();
        let mut stdout_buffer = [0u8; 32 * 1024];
        let mut stderr_buffer = [0u8; 32 * 1024];
        self.set_nonblocking()?;
        let mut last_progress = Instant::now();
        let read_result = (|| -> Result<(), String> {
            loop {
                self.check_cancelled()?;
                if last_progress.elapsed() > idle_timeout {
                    return Err(format!(
                        "Remote command timed out after {} seconds without output",
                        idle_timeout.as_secs()
                    ));
                }
                let mut made_progress = false;
                match channel.read(&mut stdout_buffer) {
                    Ok(size) if size > 0 => {
                        append_output(&mut stdout, &stdout_buffer[..size], output_limit);
                        made_progress = true;
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) => return Err(format!("Could not read remote output: {error}")),
                }
                match stderr_channel.read(&mut stderr_buffer) {
                    Ok(size) if size > 0 => {
                        append_output(&mut stderr, &stderr_buffer[..size], output_limit);
                        made_progress = true;
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) => {
                        return Err(format!("Could not read remote error output: {error}"))
                    }
                }
                if channel.eof() {
                    break;
                }
                if made_progress {
                    last_progress = Instant::now();
                }
                if !made_progress {
                    thread::sleep(Duration::from_millis(25));
                }
            }
            Ok(())
        })();
        let blocking_result = self.set_blocking();
        read_result?;
        blocking_result?;
        self.check_cancelled()?;
        channel
            .wait_close()
            .map_err(|error| format!("Could not close remote command: {error}"))?;
        let exit_code = channel.exit_status().unwrap_or(-1);
        Ok(ExecOutput {
            stdout: String::from_utf8_lossy(&stdout).to_string(),
            stderr: String::from_utf8_lossy(&stderr).to_string(),
            exit_code,
        })
    }

    pub fn exec_ok(&mut self, command: &str) -> Result<String, String> {
        let output = self.exec(command)?;
        if output.exit_code != 0 {
            return Err(command_error(&output));
        }
        Ok(output.stdout)
    }

    pub fn open_channel(&mut self) -> Result<Channel, String> {
        self.session
            .channel_session()
            .map_err(|error| format!("Could not open SSH terminal channel: {error}"))
    }

    pub fn direct_tcpip(&mut self, host: &str, port: u16) -> Result<Channel, String> {
        self.session
            .channel_direct_tcpip(host, port, None)
            .map_err(|error| format!("Could not open forwarded SSH channel: {error}"))
    }

    pub fn sftp(&self) -> Result<Sftp, String> {
        self.session
            .sftp()
            .map_err(|error| format!("Could not open SFTP subsystem: {error}"))
    }

    pub fn request_pty(channel: &mut Channel, cols: u32, rows: u32) -> Result<(), String> {
        channel
            .request_pty("xterm-256color", None, Some((cols, rows, 0, 0)))
            .map_err(|error| format!("Could not allocate a remote terminal: {error}"))
    }

    pub fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    pub fn set_nonblocking(&mut self) -> Result<(), String> {
        // Keep the TCP stream itself blocking. Toggling a cloned stream can
        // leave libssh2's transport nonblocking after a command completes,
        // which prevents a later SFTP subsystem from initializing reliably.
        self.session.set_blocking(false);
        Ok(())
    }

    fn set_blocking(&mut self) -> Result<(), String> {
        self.session.set_blocking(true);
        Ok(())
    }

    pub fn disconnect(&self) -> Result<(), String> {
        self.session
            .disconnect(None, "Disconnected by Serverbox", None)
            .map_err(|error| format!("Could not disconnect SSH session: {error}"))
    }
}

fn append_output(buffer: &mut Vec<u8>, chunk: &[u8], limit: Option<usize>) {
    let Some(limit) = limit else {
        buffer.extend_from_slice(chunk);
        return;
    };
    let remaining = limit.saturating_sub(buffer.len());
    buffer.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
}

fn open_session(
    profile: &ServerProfile,
    cancellation: Option<&Arc<AtomicBool>>,
    store: &Store,
    visited: &mut Vec<String>,
) -> Result<Session, String> {
    ensure_not_cancelled(cancellation)?;
    let tcp = if let Some(jump_host_id) = profile.jump_host_id.as_deref() {
        let jump_profile = store
            .get_server(jump_host_id)
            .map_err(|_| format!("The bastion selected for {} no longer exists", profile.name))?;
        // Bastion hops are always verified against known_hosts; only the
        // first-contact flow skips verification, and only for its own target.
        let jump_client = SshClient::connect_profile(&jump_profile, cancellation, store, visited)
            .map_err(|error| {
            format!("Could not connect through {}: {error}", jump_profile.name)
        })?;
        jump_stream(jump_client, profile, cancellation.cloned())?
    } else {
        direct_stream(profile, cancellation)?
    };
    ensure_not_cancelled(cancellation)?;
    tcp.set_read_timeout(Some(COMMAND_TIMEOUT)).ok();
    tcp.set_write_timeout(Some(COMMAND_TIMEOUT)).ok();
    let mut session =
        Session::new().map_err(|error| format!("Could not create SSH session: {error}"))?;
    session.set_tcp_stream(tcp);
    session.set_timeout(COMMAND_TIMEOUT.as_millis().min(u32::MAX as u128) as u32);
    session
        .handshake()
        .map_err(|error| format!("SSH handshake failed: {error}"))?;
    ensure_not_cancelled(cancellation)?;
    Ok(session)
}

fn direct_stream(
    profile: &ServerProfile,
    cancellation: Option<&Arc<AtomicBool>>,
) -> Result<TcpStream, String> {
    let address = format!("{}:{}", profile.host, profile.port);
    let address = address
        .to_socket_addrs()
        .map_err(|error| format!("Could not resolve {}: {error}", profile.host))?
        .next()
        .ok_or_else(|| format!("Could not resolve {}", profile.host))?;
    ensure_not_cancelled(cancellation)?;
    TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
        .map_err(|error| format!("Could not reach {}: {error}", profile.host))
}

fn jump_stream(
    mut jump_client: SshClient,
    target: &ServerProfile,
    cancellation: Option<Arc<AtomicBool>>,
) -> Result<TcpStream, String> {
    ensure_not_cancelled(cancellation.as_ref())?;
    let channel = jump_client.direct_tcpip(&target.host, target.port)?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| format!("Could not prepare the bastion relay: {error}"))?;
    let relay_address = listener
        .local_addr()
        .map_err(|error| format!("Could not prepare the bastion relay: {error}"))?;
    let transport = TcpStream::connect(relay_address)
        .map_err(|error| format!("Could not prepare the bastion relay: {error}"))?;
    let (relay, _) = listener
        .accept()
        .map_err(|error| format!("Could not prepare the bastion relay: {error}"))?;
    thread::spawn(move || {
        if let Err(error) = relay_jump(&mut jump_client, channel, relay, cancellation.as_ref()) {
            eprintln!("Serverbox bastion relay closed: {error}");
        }
    });
    Ok(transport)
}

fn relay_jump(
    client: &mut SshClient,
    mut channel: Channel,
    mut socket: TcpStream,
    cancellation: Option<&Arc<AtomicBool>>,
) -> Result<(), String> {
    socket
        .set_nonblocking(true)
        .map_err(|error| format!("Could not configure the bastion relay: {error}"))?;
    client.set_nonblocking()?;
    let mut socket_buffer = [0u8; 32 * 1024];
    let mut channel_buffer = [0u8; 32 * 1024];
    let mut to_channel = Vec::new();
    let mut to_socket = Vec::new();
    let mut socket_eof = false;
    let mut sent_eof = false;
    let mut next_keepalive =
        Instant::now() + Duration::from_secs(KEEPALIVE_INTERVAL_SECONDS.into());
    loop {
        ensure_not_cancelled(cancellation)?;
        let mut progressed = false;
        if Instant::now() >= next_keepalive {
            let _ = client.session_mut().keepalive_send();
            next_keepalive =
                Instant::now() + Duration::from_secs(KEEPALIVE_INTERVAL_SECONDS.into());
        }
        if !socket_eof && to_channel.len() < 256 * 1024 {
            match socket.read(&mut socket_buffer) {
                Ok(0) => socket_eof = true,
                Ok(size) => {
                    to_channel.extend_from_slice(&socket_buffer[..size]);
                    progressed = true;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(format!("Bastion relay read failed: {error}")),
            }
        }
        if !to_channel.is_empty() {
            match channel.write(&to_channel) {
                Ok(size) => {
                    to_channel.drain(..size);
                    progressed = true;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(format!("Bastion channel write failed: {error}")),
            }
        } else if socket_eof && !sent_eof {
            let _ = channel.send_eof();
            sent_eof = true;
        }
        if to_socket.len() < 256 * 1024 {
            match channel.read(&mut channel_buffer) {
                Ok(size) if size > 0 => {
                    to_socket.extend_from_slice(&channel_buffer[..size]);
                    progressed = true;
                }
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(format!("Bastion channel read failed: {error}")),
            }
        }
        if !to_socket.is_empty() {
            match socket.write(&to_socket) {
                Ok(size) => {
                    to_socket.drain(..size);
                    progressed = true;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(format!("Bastion relay write failed: {error}")),
            }
        }
        if channel.eof() && to_socket.is_empty() {
            return Ok(());
        }
        if !progressed {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn authenticate(session: &Session, profile: &ServerProfile, store: &Store) -> Result<(), String> {
    match profile.auth_method {
        AuthMethod::Password => {
            let password =
                Zeroizing::new(store.get_secret(&profile.id, "password")?.ok_or_else(|| {
                    format!(
                        "No password is stored for {}. Edit its connection to add it.",
                        profile.name
                    )
                })?);
            session
                .userauth_password(&profile.username, &password)
                .map_err(|error| {
                    format!(
                        "Password authentication failed for {}: {error}",
                        profile.name
                    )
                })?;
        }
        AuthMethod::PrivateKey => {
            let key_path = profile
                .key_path
                .as_deref()
                .ok_or_else(|| format!("Choose an SSH private key for {}", profile.name))?;
            let key_path = expand_path(key_path);
            if !key_path.exists() {
                return Err(format!(
                    "The SSH private key does not exist: {}",
                    key_path.display()
                ));
            }
            let passphrase = store
                .get_secret(&profile.id, "key-passphrase")?
                .map(Zeroizing::new);
            session
                .userauth_pubkey_file(
                    &profile.username,
                    None,
                    &key_path,
                    passphrase.as_deref().map(|value| value.as_str()),
                )
                .map_err(|error| {
                    format!(
                        "SSH key authentication failed for {}: {error}",
                        profile.name
                    )
                })?;
        }
    }
    if !session.authenticated() {
        return Err(format!(
            "SSH authentication was rejected by {}",
            profile.name
        ));
    }
    Ok(())
}

fn verify_host_key(session: &Session, profile: &ServerProfile) -> Result<(), String> {
    let Some((key, key_type)) = session.host_key() else {
        return Err("The SSH server did not present a host key".to_string());
    };
    let Some(home) = dirs::home_dir() else {
        return Err("Could not locate your home directory for SSH host verification".to_string());
    };
    let ssh_dir = home.join(".ssh");
    let known_hosts_path = ssh_dir.join("known_hosts");
    let mut known_hosts = session
        .known_hosts()
        .map_err(|error| format!("Could not initialize SSH host verification: {error}"))?;
    if known_hosts_path.exists() {
        known_hosts
            .read_file(&known_hosts_path, KnownHostFileKind::OpenSSH)
            .map_err(|error| format!("Could not read ~/.ssh/known_hosts: {error}"))?;
    }
    match known_hosts.check_port(&profile.host, profile.port, key) {
        CheckResult::Match => Ok(()),
        CheckResult::Mismatch => {
            let old_fingerprints = mismatched_fingerprints(session, &known_hosts, profile, key);
            Err(format!(
                "HOST_KEY_MISMATCH:{}",
                json!({
                    "host": profile.host,
                    "port": profile.port,
                    "keyType": format!("{key_type:?}"),
                    "oldFingerprints": old_fingerprints,
                    "newFingerprint": host_key_fingerprint(key),
                })
            ))
        }
        CheckResult::Failure => Err(format!(
            "Could not verify the SSH host key for {}",
            profile.host
        )),
        CheckResult::NotFound => {
            // First contact never silently trusts a key. Surface the
            // fingerprint so the frontend can ask the user to review it
            // before anything is written to ~/.ssh/known_hosts.
            Err(format!(
                "HOST_KEY_UNKNOWN:{}",
                json!({
                    "host": profile.host,
                    "port": profile.port,
                    "keyType": format!("{key_type:?}"),
                    "fingerprint": host_key_fingerprint(key),
                })
            ))
        }
    }
}

/// Records a user-accepted host key by appending one line to
/// ~/.ssh/known_hosts. Appending (instead of rewriting the whole file through
/// libssh2) means a concurrent ssh-keygen or OpenSSH modification to the file
/// cannot be lost.
fn append_known_host_line(profile: &ServerProfile, key: &[u8]) -> Result<(), String> {
    let Some(home) = dirs::home_dir() else {
        return Err("Could not locate your home directory for SSH host verification".to_string());
    };
    let ssh_dir = home.join(".ssh");
    fs::create_dir_all(&ssh_dir).map_err(|error| format!("Could not create ~/.ssh: {error}"))?;
    let algorithm = host_key_algorithm(key)
        .ok_or_else(|| "Could not determine the SSH host key algorithm".to_string())?;
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(key);
    let host = if profile.port == 22 {
        profile.host.clone()
    } else {
        format!("[{}]:{}", profile.host, profile.port)
    };
    let line = format!("{host} {algorithm} {encoded} added by Serverbox\n");
    let known_hosts_path = ssh_dir.join("known_hosts");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&known_hosts_path)
        .map_err(|error| format!("Could not open ~/.ssh/known_hosts: {error}"))?;
    file.write_all(line.as_bytes())
        .map_err(|error| format!("Could not save ~/.ssh/known_hosts: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("Could not save ~/.ssh/known_hosts: {error}"))
}

/// Extracts the algorithm name (for example `ssh-ed25519`) from a raw SSH key
/// blob. The wire format begins with a length-prefixed algorithm string.
fn host_key_algorithm(key: &[u8]) -> Option<String> {
    if key.len() < 4 {
        return None;
    }
    let length = u32::from_be_bytes([key[0], key[1], key[2], key[3]]) as usize;
    if length == 0 || key.len() < 4 + length {
        return None;
    }
    std::str::from_utf8(&key[4..4 + length])
        .ok()
        .map(str::to_string)
}

/// Records the host key the user explicitly accepted from the first-contact
/// prompt. Walks the bastion chain to find which hop presents the expected
/// key, re-verifies the presented fingerprint, then appends it to known_hosts.
pub fn accept_host_key(
    store: &Store,
    server_id: &str,
    expected_host: &str,
    expected_port: u16,
    expected_fingerprint: &str,
) -> Result<(), String> {
    let mut chain = Vec::new();
    let mut current = store.get_server(server_id)?;
    let mut seen = std::collections::HashSet::new();
    loop {
        if !seen.insert(current.id.clone()) {
            return Err("Bastion profiles contain a connection cycle".to_string());
        }
        let next = current.jump_host_id.clone();
        chain.push(current);
        let Some(next) = next else { break };
        current = store.get_server(&next)?;
    }
    for candidate in chain.into_iter().rev() {
        if candidate.host != expected_host || candidate.port != expected_port {
            continue;
        }
        // Establish the transport again without authenticating to the target.
        // Bastion hops are still authenticated and verified by `open_session`.
        let mut visited = vec![candidate.id.clone()];
        let session = open_session(&candidate, None, store, &mut visited)?;
        let Some((key, _)) = session.host_key() else {
            return Err("The SSH server did not present a host key".to_string());
        };
        let fingerprint = host_key_fingerprint(key);
        if fingerprint != expected_fingerprint {
            return Err(format!(
                "The SSH host key for {} changed before it could be accepted. Expected {expected_fingerprint}, but the server now presents {fingerprint}. Connect again to review it.",
                candidate.host
            ));
        }
        return append_known_host_line(&candidate, key);
    }
    Err("The SSH host-key prompt no longer matches this bastion chain".to_string())
}

fn host_key_fingerprint(key: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(key)))
}

fn host_entry_matches(
    session: &Session,
    known_hosts: &ssh2::KnownHosts,
    entry: &ssh2::Host,
    profile: &ServerProfile,
    presented_key: &[u8],
) -> Result<bool, String> {
    let line = known_hosts
        .write_string(entry, KnownHostFileKind::OpenSSH)
        .map_err(|error| format!("Could not inspect the saved SSH host key: {error}"))?;
    let mut single = session
        .known_hosts()
        .map_err(|error| format!("Could not inspect the saved SSH host key: {error}"))?;
    single
        .read_str(&line, KnownHostFileKind::OpenSSH)
        .map_err(|error| format!("Could not inspect the saved SSH host key: {error}"))?;
    Ok(matches!(
        single.check_port(&profile.host, profile.port, presented_key),
        CheckResult::Match | CheckResult::Mismatch
    ))
}

fn mismatched_fingerprints(
    session: &Session,
    known_hosts: &ssh2::KnownHosts,
    profile: &ServerProfile,
    presented_key: &[u8],
) -> Vec<String> {
    known_hosts
        .hosts()
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| {
            host_entry_matches(session, known_hosts, entry, profile, presented_key).unwrap_or(false)
        })
        .filter_map(|entry| {
            base64::engine::general_purpose::STANDARD
                .decode(entry.key())
                .ok()
        })
        .map(|key| host_key_fingerprint(&key))
        .collect()
}

pub fn replace_host_key(
    store: &Store,
    server_id: &str,
    expected_host: &str,
    expected_port: u16,
    expected_fingerprint: &str,
) -> Result<(), String> {
    let mut chain = Vec::new();
    let mut current = store.get_server(server_id)?;
    let mut seen = std::collections::HashSet::new();
    loop {
        if !seen.insert(current.id.clone()) {
            return Err("Bastion profiles contain a connection cycle".to_string());
        }
        let next = current.jump_host_id.clone();
        chain.push(current);
        let Some(next) = next else { break };
        current = store.get_server(&next)?;
    }
    let mut selected = None;
    for candidate in chain.into_iter().rev() {
        if candidate.host != expected_host || candidate.port != expected_port {
            continue;
        }
        let mut visited = vec![candidate.id.clone()];
        let session = open_session(&candidate, None, store, &mut visited)?;
        let Some((key, _)) = session.host_key() else {
            return Err("The SSH server did not present a host key".to_string());
        };
        if host_key_fingerprint(key) == expected_fingerprint {
            selected = Some((candidate, session));
            break;
        }
        verify_host_key(&session, &candidate)?;
    }
    let Some((profile, session)) = selected else {
        return Err("The SSH host-key prompt no longer matches this bastion chain".to_string());
    };
    let Some((key, key_type)) = session.host_key() else {
        return Err("The SSH server did not present a host key".to_string());
    };
    let fingerprint = host_key_fingerprint(key);
    if fingerprint != expected_fingerprint {
        return Err(format!(
            "The SSH host key changed again. Expected {expected_fingerprint}, but the server now presents {fingerprint}."
        ));
    }
    let Some(home) = dirs::home_dir() else {
        return Err("Could not locate your home directory for SSH host verification".to_string());
    };
    let ssh_dir = home.join(".ssh");
    let known_hosts_path = ssh_dir.join("known_hosts");
    let mut known_hosts = session
        .known_hosts()
        .map_err(|error| format!("Could not initialize SSH host verification: {error}"))?;
    if known_hosts_path.exists() {
        known_hosts
            .read_file(&known_hosts_path, KnownHostFileKind::OpenSSH)
            .map_err(|error| format!("Could not read ~/.ssh/known_hosts: {error}"))?;
    }
    if !matches!(
        known_hosts.check_port(&profile.host, profile.port, key),
        CheckResult::Mismatch | CheckResult::Match
    ) {
        return Err(format!(
            "The saved SSH host key for {} changed before it could be replaced. Connect again to review it.",
            profile.host
        ));
    }
    loop {
        let matching_entry = known_hosts
            .hosts()
            .map_err(|error| format!("Could not inspect saved SSH host keys: {error}"))?
            .into_iter()
            .find(|entry| {
                host_entry_matches(&session, &known_hosts, entry, &profile, key).unwrap_or(false)
            });
        let Some(entry) = matching_entry else { break };
        known_hosts
            .remove(&entry)
            .map_err(|error| format!("Could not remove the old SSH host key: {error}"))?;
    }
    fs::create_dir_all(&ssh_dir).map_err(|error| format!("Could not create ~/.ssh: {error}"))?;
    let host = if profile.port == 22 {
        profile.host.clone()
    } else {
        format!("[{}]:{}", profile.host, profile.port)
    };
    known_hosts
        .add(&host, key, "replaced by Serverbox", key_type.into())
        .map_err(|error| format!("Could not record the new SSH host key: {error}"))?;
    known_hosts
        .write_file(&known_hosts_path, KnownHostFileKind::OpenSSH)
        .map_err(|error| format!("Could not save ~/.ssh/known_hosts: {error}"))
}

pub fn with_client<T, F>(
    store: &Store,
    server_id: &str,
    operation_id: Option<&str>,
    operation: F,
) -> Result<T, String>
where
    F: FnOnce(&mut SshClient, &ServerProfile) -> Result<T, String>,
{
    let profile = store.get_server(server_id)?;
    let operation_handle = begin_operation(operation_id);
    let mut last_error = None;
    let mut connected_client = None;
    let profile_key = profile_key(&profile);
    for attempt in 0..2 {
        if let Err(error) =
            ensure_not_cancelled(operation_handle.as_ref().map(|handle| &handle.cancelled))
        {
            finish_operation(operation_handle);
            return Err(error);
        }
        match cached_client(
            store,
            server_id,
            &profile,
            operation_handle.as_ref().map(|handle| &handle.cancelled),
        ) {
            Ok((client, reused)) => {
                if reused {
                    let usable = {
                        let mut client_guard = match lock_client(
                            &client,
                            operation_handle.as_ref().map(|handle| &handle.cancelled),
                        ) {
                            Ok(client) => client,
                            Err(error) => {
                                finish_operation(operation_handle);
                                return Err(error);
                            }
                        };
                        client_guard.set_cancellation(
                            operation_handle
                                .as_ref()
                                .map(|handle| handle.cancelled.clone()),
                        );
                        let usable = client_guard
                            .exec_with_input_limited_timeout(
                                ":",
                                None,
                                Some(1024),
                                CONNECTION_PROBE_TIMEOUT,
                            )
                            .is_ok_and(|output| output.exit_code == 0);
                        client_guard.clear_cancellation();
                        usable
                    };
                    if !usable {
                        invalidate_cached(server_id, &profile_key, &client);
                        last_error =
                            Some("The cached SSH connection is no longer usable".to_string());
                        if attempt == 0 {
                            continue;
                        }
                        break;
                    }
                }
                connected_client = Some(client);
                break;
            }
            Err(error) => {
                last_error = Some(error);
                if attempt == 0
                    && last_error
                        .as_deref()
                        .is_some_and(is_retryable_connection_error)
                {
                    thread::sleep(Duration::from_millis(220));
                } else {
                    break;
                }
            }
        }
    }
    let Some(client) = connected_client else {
        finish_operation(operation_handle);
        return Err(last_error.unwrap_or_else(|| "SSH connection failed".to_string()));
    };
    let (result, connection_usable) = {
        let mut client_guard = match lock_client(
            &client,
            operation_handle.as_ref().map(|handle| &handle.cancelled),
        ) {
            Ok(client) => client,
            Err(error) => {
                finish_operation(operation_handle);
                return Err(error);
            }
        };
        client_guard.set_cancellation(
            operation_handle
                .as_ref()
                .map(|handle| handle.cancelled.clone()),
        );
        let result = operation(&mut client_guard, &profile);
        client_guard.clear_cancellation();
        let result = result.and_then(|value| {
            ensure_not_cancelled(operation_handle.as_ref().map(|handle| &handle.cancelled))?;
            Ok(value)
        });
        let connection_usable = result.is_ok()
            || matches!(&result, Err(error) if error == OPERATION_CANCELLED)
            || client_guard.connection_is_usable();
        (result, connection_usable)
    };
    match &result {
        Err(_) if !connection_usable => invalidate_cached(server_id, &profile_key, &client),
        Ok(_) => {
            let _ = store.mark_connected(server_id);
        }
        _ => {}
    }
    finish_operation(operation_handle);
    result
}

fn is_retryable_connection_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    ![
        "authentication failed",
        "authentication was rejected",
        "no password is stored",
        "private key does not exist",
        "choose an ssh private key",
        "host_key_",
        "master_password_",
    ]
    .iter()
    .any(|message| error.contains(message))
}

pub fn cancel_operation(operation_id: &str) -> Result<(), String> {
    let mut states = operations()
        .lock()
        .map_err(|_| "SSH operation lock was poisoned".to_string())?;
    prune_pending_cancellations(&mut states);
    let state = states
        .entry(operation_id.to_string())
        .or_insert_with(|| OperationState {
            cancelled: Arc::new(AtomicBool::new(false)),
            pending_since: Some(Instant::now()),
        });
    state.cancelled.store(true, Ordering::SeqCst);
    prune_pending_cancellations(&mut states);
    Ok(())
}

pub fn disconnect_server(server_id: &str) -> Result<(), String> {
    let cached = connections()
        .lock()
        .map_err(|_| "SSH connection lock was poisoned".to_string())?
        .remove(server_id);
    if let Some(cached) = cached {
        if let Ok(client) = cached.client.try_lock() {
            let _ = client.disconnect();
        }
    }
    Ok(())
}

pub fn disconnect_all() {
    let cached = connections().lock().map(|mut clients| {
        clients
            .drain()
            .map(|(_, cached)| cached)
            .collect::<Vec<_>>()
    });
    let Ok(cached) = cached else {
        return;
    };
    for cached in cached {
        if let Ok(client) = cached.client.try_lock() {
            let _ = client.disconnect();
        }
    }
}

pub(crate) fn begin_operation(operation_id: Option<&str>) -> Option<OperationHandle> {
    let id = operation_id?.to_string();
    let cancelled = if let Ok(mut states) = operations().lock() {
        let state = states.entry(id.clone()).or_insert_with(|| OperationState {
            cancelled: Arc::new(AtomicBool::new(false)),
            pending_since: None,
        });
        state.pending_since = None;
        state.cancelled.clone()
    } else {
        Arc::new(AtomicBool::new(false))
    };
    Some(OperationHandle { id, cancelled })
}

pub(crate) fn finish_operation(operation: Option<OperationHandle>) {
    let Some(operation) = operation else {
        return;
    };
    if let Ok(mut states) = operations().lock() {
        if states
            .get(&operation.id)
            .is_some_and(|state| Arc::ptr_eq(&state.cancelled, &operation.cancelled))
        {
            states.remove(&operation.id);
        }
    }
}

fn prune_pending_cancellations(states: &mut HashMap<String, OperationState>) {
    let now = Instant::now();
    states.retain(|_, state| {
        state
            .pending_since
            .is_none_or(|created| now.duration_since(created) < PENDING_CANCELLATION_TTL)
    });

    let pending_count = states
        .values()
        .filter(|state| state.pending_since.is_some())
        .count();
    if pending_count <= MAX_PENDING_CANCELLATIONS {
        return;
    }
    let mut pending = states
        .iter()
        .filter_map(|(id, state)| state.pending_since.map(|created| (id.clone(), created)))
        .collect::<Vec<_>>();
    pending.sort_unstable_by_key(|(_, created)| *created);
    for (id, _) in pending
        .into_iter()
        .take(pending_count - MAX_PENDING_CANCELLATIONS)
    {
        states.remove(&id);
    }
}

pub(crate) fn ensure_not_cancelled(cancellation: Option<&Arc<AtomicBool>>) -> Result<(), String> {
    if cancellation.is_some_and(|value| value.load(Ordering::SeqCst)) {
        Err(OPERATION_CANCELLED.to_string())
    } else {
        Ok(())
    }
}

pub(crate) fn profile_key(profile: &ServerProfile) -> String {
    format!(
        "{}:{}:{}:{:?}:{}:{}",
        profile.host,
        profile.port,
        profile.username,
        profile.auth_method,
        profile.key_path.as_deref().unwrap_or_default(),
        profile.jump_host_id.as_deref().unwrap_or_default()
    )
}

fn cached_client(
    store: &Store,
    server_id: &str,
    profile: &ServerProfile,
    cancellation: Option<&Arc<AtomicBool>>,
) -> Result<(Arc<Mutex<SshClient>>, bool), String> {
    let key = profile_key(profile);
    if let Some(client) = connections()
        .lock()
        .map_err(|_| "SSH connection lock was poisoned".to_string())?
        .get(server_id)
        .and_then(|cached| (cached.profile_key == key).then(|| cached.client.clone()))
    {
        return Ok((client, true));
    }
    connections()
        .lock()
        .map_err(|_| "SSH connection lock was poisoned".to_string())?
        .remove(server_id);
    let client = Arc::new(Mutex::new(SshClient::connect_with_cancellation(
        profile,
        cancellation,
        store,
    )?));
    connections()
        .lock()
        .map_err(|_| "SSH connection lock was poisoned".to_string())?
        .insert(
            server_id.to_string(),
            CachedClient {
                profile_key: key,
                client: client.clone(),
            },
        );
    Ok((client, false))
}

fn lock_client<'a>(
    client: &'a Arc<Mutex<SshClient>>,
    cancellation: Option<&Arc<AtomicBool>>,
) -> Result<std::sync::MutexGuard<'a, SshClient>, String> {
    loop {
        ensure_not_cancelled(cancellation)?;
        match client.try_lock() {
            Ok(client) => return Ok(client),
            Err(TryLockError::WouldBlock) => thread::sleep(Duration::from_millis(25)),
            Err(TryLockError::Poisoned(_)) => {
                return Err("SSH connection lock was poisoned".to_string())
            }
        }
    }
}

fn invalidate_cached(
    server_id: &str,
    expected_profile_key: &str,
    expected_client: &Arc<Mutex<SshClient>>,
) {
    if let Ok(mut clients) = connections().lock() {
        if clients.get(server_id).is_some_and(|cached| {
            cached.profile_key == expected_profile_key
                && Arc::ptr_eq(&cached.client, expected_client)
        }) {
            clients.remove(server_id);
        }
    }
}

/// Control markers that must never appear inside remote-derived error text.
/// A compromised host could otherwise forge them onto stderr of any failing
/// command and inject into credential or host-key security flows.
const CONTROL_MARKERS: [&str; 5] = [
    "HOST_KEY_MISMATCH:",
    "HOST_KEY_UNKNOWN:",
    "MASTER_PASSWORD_REQUIRED:",
    "MASTER_PASSWORD_SETUP_REQUIRED:",
    "MASTER_PASSWORD_INVALID:",
];

fn sanitize_remote_message(message: &str) -> String {
    let mut sanitized = message.to_string();
    for marker in CONTROL_MARKERS {
        sanitized = sanitized.replace(marker, "");
    }
    sanitized
}

pub fn command_error(output: &ExecOutput) -> String {
    let message = sanitize_remote_message(output.stderr.trim());
    if !message.is_empty() {
        return message;
    }
    let stdout = sanitize_remote_message(output.stdout.trim());
    if !stdout.is_empty() {
        return stdout;
    }
    match output.exit_code {
        126 => "The remote program exists but could not be executed (exit status 126). Check its permissions and architecture.".to_string(),
        127 => "The remote command was not found (exit status 127). The required program may not be installed or available in PATH.".to_string(),
        130 => "The remote command was interrupted (exit status 130).".to_string(),
        137 => "The remote command was killed, commonly because the system ran out of memory (exit status 137).".to_string(),
        143 => "The remote command was terminated (exit status 143).".to_string(),
        status => format!("The remote command failed with exit status {status} and returned no diagnostic output."),
    }
}

pub(crate) fn bounded_output(mut value: String) -> String {
    if value.len() <= MAX_LOG_OUTPUT_BYTES {
        return value;
    }
    let mut boundary = MAX_LOG_OUTPUT_BYTES;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    value.push_str("\n\n[Output truncated at 1 MB by Serverbox]");
    value
}

pub(crate) fn is_permission_error(output: &ExecOutput) -> bool {
    let message = format!("{}\n{}", output.stderr, output.stdout).to_ascii_lowercase();
    is_permission_message(&message)
}

pub(crate) fn is_permission_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "permission denied",
        "insufficient permissions",
        "operation not permitted",
        "not authorized",
        "access denied",
        "must be root",
    ]
    .iter()
    .any(|pattern| message.contains(pattern))
}

pub(crate) fn execute_privileged_posix_script_bounded(
    client: &mut SshClient,
    profile: &ServerProfile,
    store: &Store,
    script: &str,
    arguments: &[&str],
    max_output_bytes: usize,
) -> Result<String, String> {
    if client
        .exec("id -u")
        .map(|output| output.stdout.trim() == "0")
        .unwrap_or(false)
    {
        return client.exec_posix_script_bounded(script, arguments, max_output_bytes);
    }
    if client.exec("sudo -n true")?.exit_code == 0 {
        let command = posix_script_command("sudo -n env LC_ALL=C sh -s", arguments);
        return execute_posix_script_bounded(
            client,
            &command,
            script.as_bytes(),
            max_output_bytes,
            COMMAND_TIMEOUT,
        );
    }
    let password = Zeroizing::new(store.get_secret(&profile.id, "sudo-password")?.ok_or_else(
        || {
            "This action needs sudo. Add a sudo password to the server connection first."
                .to_string()
        },
    )?);
    // One remote shell owns both sudo invocations, so sudo's non-TTY
    // parent-process timestamp remains valid. The shell reads the password
    // line before validation, keeping a rejected password from consuming any
    // of the script payload that follows it on stdin.
    let command = sudo_password_command(&posix_script_command(
        "sudo -n env LC_ALL=C sh -s",
        arguments,
    ));
    let input = sudo_password_input(&password, script.as_bytes());
    let output = client.exec_with_input_limited(
        &command,
        Some(input.as_slice()),
        Some(max_output_bytes.saturating_add(1)),
    )?;
    if sudo_password_was_rejected(&output) {
        return Err(sudo_password_rejected_error());
    }
    validate_script_output(output, max_output_bytes)
}

pub(crate) fn validate_sudo_password(client: &mut SshClient, password: &str) -> Result<(), String> {
    let input = sudo_password_input(password, &[]);
    let output = client.exec_with_input_limited(
        "LC_ALL=C sudo -S -k -p '' -v",
        Some(input.as_slice()),
        Some(64 * 1024),
    )?;
    if output.exit_code == 0 {
        Ok(())
    } else if sudo_password_was_rejected(&output) {
        Err(sudo_password_rejected_error())
    } else {
        Err(command_error(&output))
    }
}

/// Wraps a command that also consumes stdin. The first input line is read by
/// the shell and piped only to sudo validation; the command receives the
/// untouched payload after the newline. Both sudo processes share the same
/// parent shell, which is required by stock non-TTY sudo timestamp scoping.
fn sudo_password_command(command: &str) -> String {
    let script = format!(
        "IFS= read -r serverbox_sudo_password || exit 1\n\
         if printf '%s\\n' \"$serverbox_sudo_password\" | sudo -S -k -p '' -v; then\n\
           unset serverbox_sudo_password\n\
           {command}\n\
         else\n\
           unset serverbox_sudo_password\n\
           exit 1\n\
         fi"
    );
    format!("LC_ALL=C sh -c {}", quote_shell(&script))
}

pub(crate) fn sudo_password_input(password: &str, payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut input = Zeroizing::new(Vec::with_capacity(password.len() + 1 + payload.len()));
    input.extend_from_slice(password.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(payload);
    input
}

pub(crate) fn sudo_password_was_rejected(output: &ExecOutput) -> bool {
    let message = format!("{}\n{}", output.stderr, output.stdout).to_ascii_lowercase();
    message.contains("sorry, try again")
        || message.contains("no password was provided")
        || message.contains("incorrect password")
}

fn sudo_password_rejected_error() -> String {
    "The stored sudo password was rejected. Update it in the server connection settings."
        .to_string()
}

fn posix_script_command(command: &str, arguments: &[&str]) -> String {
    let arguments = arguments
        .iter()
        .map(|argument| quote_shell(argument))
        .collect::<Vec<_>>()
        .join(" ");
    if arguments.is_empty() {
        command.to_string()
    } else {
        format!("{command} -- {arguments}")
    }
}

fn execute_posix_script_bounded(
    client: &mut SshClient,
    command: &str,
    script: &[u8],
    max_output_bytes: usize,
    idle_timeout: Duration,
) -> Result<String, String> {
    let output = client.exec_with_input_limited_timeout(
        command,
        Some(script),
        Some(max_output_bytes.saturating_add(1)),
        idle_timeout,
    )?;
    validate_script_output(output, max_output_bytes)
}

fn validate_script_output(output: ExecOutput, max_output_bytes: usize) -> Result<String, String> {
    if output.stdout.len() > max_output_bytes || output.stderr.len() > max_output_bytes {
        return Err(format!(
            "Remote script output exceeded the {max_output_bytes} byte limit"
        ));
    }
    if output.exit_code == 0 {
        Ok(output.stdout)
    } else {
        Err(command_error(&output))
    }
}

pub fn quote_shell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn expand_path(value: &str) -> PathBuf {
    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(value)
}

pub fn detect_capabilities(client: &mut SshClient) -> Result<ServerCapabilities, String> {
    if let Some(capabilities) = client.capabilities.as_ref() {
        return Ok(capabilities.clone());
    }
    let probe = client
        .exec(
            r#"printf 'distro\t'; os_release=; if [ -r /etc/os-release ]; then os_release=/etc/os-release; elif [ -r /usr/lib/os-release ]; then os_release=/usr/lib/os-release; fi; if [ -n "$os_release" ]; then . "$os_release"; printf '%s' "${PRETTY_NAME:-${NAME:-Linux}}"; else uname -s 2>/dev/null || printf Linux; fi; printf '\narchitecture\t'; uname -m 2>/dev/null || printf unknown; if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then printf '\ncommand\tsystemctl'; fi; for name in docker podman sudo ss netstat journalctl crontab; do if command -v "$name" >/dev/null 2>&1; then printf '\ncommand\t%s' "$name"; fi; done; printf '\nroot\t'; if [ "$(id -u 2>/dev/null)" = 0 ]; then printf true; else printf false; fi; printf '\nlogread\t'; if command -v logread >/dev/null 2>&1 && logread -l 1 >/dev/null 2>&1; then printf true; else printf false; fi; printf '\ncoreutils\t'; case "$(ls --version 2>/dev/null | head -n 1)" in *'GNU coreutils'*) printf GNU ;; *) if command -v busybox >/dev/null 2>&1; then printf BusyBox; else printf POSIX/other; fi ;; esac; printf '\npackageManager\t'; for name in apt-get dnf yum zypper pacman apk; do if command -v "$name" >/dev/null 2>&1; then printf '%s' "$name"; break; fi; done"#,
        )?
        .stdout;
    let capabilities = parse_capabilities_probe(&probe);
    client.capabilities = Some(capabilities.clone());
    Ok(capabilities)
}

pub(crate) fn parse_capabilities_probe(probe: &str) -> ServerCapabilities {
    let mut distro = None;
    let mut architecture = "unknown".to_string();
    let mut systemd = false;
    let mut docker = false;
    let mut podman = false;
    let mut sudo = false;
    let mut network_tool = None;
    let mut journalctl = false;
    let mut logread = false;
    let mut cron = false;
    let mut root = false;
    let mut coreutils_variant = "POSIX/other".to_string();
    let mut package_manager = None;
    for line in probe.lines() {
        let Some((field, value)) = line.split_once('\t') else {
            continue;
        };
        match field {
            "distro" if !value.trim().is_empty() => distro = Some(value.trim().to_string()),
            "architecture" if !value.trim().is_empty() => architecture = value.trim().to_string(),
            "command" => match value.trim() {
                "systemctl" => systemd = true,
                "docker" => docker = true,
                "podman" => podman = true,
                "sudo" => sudo = true,
                "ss" | "netstat" if network_tool.is_none() => {
                    network_tool = Some(value.trim().to_string())
                }
                "journalctl" => journalctl = true,
                "crontab" => cron = true,
                _ => {}
            },
            "root" => root = value.trim() == "true",
            "logread" => logread = value.trim() == "true",
            "coreutils" if !value.trim().is_empty() => coreutils_variant = value.trim().to_string(),
            "packageManager" if !value.trim().is_empty() => {
                package_manager = Some(value.trim().to_string())
            }
            _ => {}
        }
    }
    ServerCapabilities {
        distro,
        package_manager,
        init_system: if systemd {
            Some("systemd".to_string())
        } else {
            None
        },
        systemd,
        docker,
        podman,
        sudo,
        network_tool,
        journalctl,
        logread,
        cron,
        architecture,
        coreutils_variant,
        root,
    }
}

pub fn execute_privileged(
    client: &mut SshClient,
    profile: &ServerProfile,
    store: &Store,
    command: &str,
) -> Result<String, String> {
    execute_privileged_with_limit(client, profile, store, command, None, COMMAND_TIMEOUT)
}

/// Like `execute_privileged`, but tolerant of long silent stretches (builds,
/// pulls, package upgrades). Cancellation still interrupts it immediately.
pub(crate) fn execute_privileged_long(
    client: &mut SshClient,
    profile: &ServerProfile,
    store: &Store,
    command: &str,
) -> Result<String, String> {
    execute_privileged_with_limit(client, profile, store, command, None, LONG_COMMAND_TIMEOUT)
}

pub(crate) fn execute_privileged_bounded(
    client: &mut SshClient,
    profile: &ServerProfile,
    store: &Store,
    command: &str,
    max_output_bytes: usize,
) -> Result<String, String> {
    execute_privileged_with_limit(
        client,
        profile,
        store,
        command,
        Some(max_output_bytes),
        COMMAND_TIMEOUT,
    )
}

fn execute_privileged_with_limit(
    client: &mut SshClient,
    profile: &ServerProfile,
    store: &Store,
    command: &str,
    max_output_bytes: Option<usize>,
    idle_timeout: Duration,
) -> Result<String, String> {
    if client
        .exec("id -u")
        .map(|output| output.stdout.trim() == "0")
        .unwrap_or(false)
    {
        return execute_command(client, command, max_output_bytes, idle_timeout);
    }
    let direct = client.exec("sudo -n true")?;
    if direct.exit_code == 0 {
        return execute_command(
            client,
            &format!("sudo -n sh -c {}", quote_shell(command)),
            max_output_bytes,
            idle_timeout,
        );
    }
    let stored = store.get_secret(&profile.id, "sudo-password")?;
    let Some(password) = stored.filter(|value| !value.is_empty()) else {
        return Err("This action needs sudo. Add a sudo password to the server connection, or use the terminal to authenticate interactively.".to_string());
    };
    let password = Zeroizing::new(password);
    let input = sudo_password_input(&password, &[]);
    let output = client.exec_with_input_limited_timeout(
        &format!("LC_ALL=C sudo -S -k -p '' sh -c {}", quote_shell(command)),
        Some(input.as_slice()),
        max_output_bytes.map(|limit| limit.saturating_add(1)),
        idle_timeout,
    )?;
    if sudo_password_was_rejected(&output) {
        return Err(sudo_password_rejected_error());
    }
    command_output(output)
}

fn execute_command(
    client: &mut SshClient,
    command: &str,
    max_output_bytes: Option<usize>,
    idle_timeout: Duration,
) -> Result<String, String> {
    let output = match max_output_bytes {
        Some(max_output_bytes) => client.exec_with_input_limited_timeout(
            command,
            None,
            Some(max_output_bytes.saturating_add(1)),
            idle_timeout,
        )?,
        None => client.exec_with_input_limited_timeout(command, None, None, idle_timeout)?,
    };
    command_output(output)
}

fn command_output(output: ExecOutput) -> Result<String, String> {
    if output.exit_code == 0 {
        Ok(output.stdout)
    } else {
        Err(command_error(&output))
    }
}

pub fn execute_privileged_with_input(
    client: &mut SshClient,
    profile: &ServerProfile,
    store: &Store,
    command: &str,
    input: &[u8],
) -> Result<String, String> {
    if client
        .exec("id -u")
        .map(|output| output.stdout.trim() == "0")
        .unwrap_or(false)
    {
        let output = client.exec_with_input(command, Some(input))?;
        return if output.exit_code == 0 {
            Ok(output.stdout)
        } else {
            Err(command_error(&output))
        };
    }
    if client.exec("sudo -n true")?.exit_code == 0 {
        let output = client.exec_with_input(
            &format!("sudo -n sh -c {}", quote_shell(command)),
            Some(input),
        )?;
        return if output.exit_code == 0 {
            Ok(output.stdout)
        } else {
            Err(command_error(&output))
        };
    }
    let password = Zeroizing::new(store.get_secret(&profile.id, "sudo-password")?.ok_or_else(
        || {
            "This action needs sudo. Add a sudo password to the server connection first."
                .to_string()
        },
    )?);
    let sudo_command = sudo_password_command(&format!("sudo -n sh -c {}", quote_shell(command)));
    let sudo_input = sudo_password_input(&password, input);
    let output = client.exec_with_input(&sudo_command, Some(sudo_input.as_slice()))?;
    if sudo_password_was_rejected(&output) {
        return Err(sudo_password_rejected_error());
    }
    if output.exit_code == 0 {
        Ok(output.stdout)
    } else {
        Err(command_error(&output))
    }
}
