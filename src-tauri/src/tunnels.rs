use crate::models::{TunnelConfig, TunnelStatus};
use crate::ssh::SshClient;
use crate::storage::Store;
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, OnceLock,
};
use std::thread;
use std::time::Duration;

struct Runtime {
    running: Arc<AtomicBool>,
    error: Arc<Mutex<Option<String>>>,
}
static RUNTIMES: OnceLock<Mutex<HashMap<String, Runtime>>> = OnceLock::new();
fn runtimes() -> &'static Mutex<HashMap<String, Runtime>> {
    RUNTIMES.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn start(store: Store, tunnel: TunnelConfig) -> Result<TunnelStatus, String> {
    stop(&tunnel.id)?;
    let running = Arc::new(AtomicBool::new(true));
    let error = Arc::new(Mutex::new(None));
    runtimes()
        .lock()
        .map_err(|_| "Tunnel state lock was poisoned".to_string())?
        .insert(
            tunnel.id.clone(),
            Runtime {
                running: running.clone(),
                error: error.clone(),
            },
        );
    let id = tunnel.id.clone();
    thread::spawn(move || {
        let result = if tunnel.kind == "remote" {
            run_remote(&store, &tunnel, &running)
        } else {
            run_local(&store, &tunnel, &running)
        };
        if let Err(message) = result {
            if let Ok(mut current) = error.lock() {
                *current = Some(message);
            }
        }
        running.store(false, Ordering::SeqCst);
    });
    Ok(TunnelStatus {
        id,
        running: true,
        error: None,
    })
}

pub fn stop(id: &str) -> Result<(), String> {
    if let Some(runtime) = runtimes()
        .lock()
        .map_err(|_| "Tunnel state lock was poisoned".to_string())?
        .get(id)
    {
        runtime.running.store(false, Ordering::SeqCst);
    }
    Ok(())
}

pub fn stop_all() {
    if let Ok(states) = runtimes().lock() {
        for runtime in states.values() {
            runtime.running.store(false, Ordering::SeqCst);
        }
    }
}

pub fn statuses(ids: &[String]) -> Vec<TunnelStatus> {
    let Ok(states) = runtimes().lock() else {
        return vec![];
    };
    ids.iter()
        .map(|id| {
            states
                .get(id)
                .map(|runtime| TunnelStatus {
                    id: id.clone(),
                    running: runtime.running.load(Ordering::SeqCst),
                    error: runtime.error.lock().ok().and_then(|value| value.clone()),
                })
                .unwrap_or(TunnelStatus {
                    id: id.clone(),
                    running: false,
                    error: None,
                })
        })
        .collect()
}

fn run_local(
    store: &Store,
    tunnel: &TunnelConfig,
    running: &Arc<AtomicBool>,
) -> Result<(), String> {
    let listener = if tunnel.kind == "socks" {
        let addresses = loopback_bind_addresses(&tunnel.bind_host, tunnel.bind_port)?;
        TcpListener::bind(addresses.as_slice())
    } else {
        TcpListener::bind((tunnel.bind_host.as_str(), tunnel.bind_port))
    }
    .map_err(|error| {
        format!(
            "Could not bind {}:{}: {error}",
            tunnel.bind_host, tunnel.bind_port
        )
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("Could not configure tunnel listener: {error}"))?;
    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut socket, _)) => {
                let (host, port) = if tunnel.kind == "socks" {
                    match socks_target(&mut socket) {
                        Ok(target) => target,
                        Err(_) => continue,
                    }
                } else {
                    (tunnel.target_host.clone(), tunnel.target_port)
                };
                let profile = store.get_server(&tunnel.server_id)?;
                let store = store.clone();
                let running = running.clone();
                let socks = tunnel.kind == "socks";
                thread::spawn(move || {
                    match SshClient::connect_with_cancellation(&profile, None, &store).and_then(
                        |mut client| {
                            let channel = client.direct_tcpip(&host, port)?;
                            if socks {
                                socket
                                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                                    .map_err(|error| error.to_string())?;
                            }
                            client.set_nonblocking()?;
                            pump(channel, socket, &running)
                        },
                    ) {
                        Ok(()) => {}
                        Err(error) => eprintln!("Serverbox tunnel connection failed: {error}"),
                    }
                });
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(40))
            }
            Err(error) => return Err(format!("Tunnel listener failed: {error}")),
        }
    }
    Ok(())
}

fn run_remote(
    store: &Store,
    tunnel: &TunnelConfig,
    running: &Arc<AtomicBool>,
) -> Result<(), String> {
    let profile = store.get_server(&tunnel.server_id)?;
    let mut client = SshClient::connect_with_cancellation(&profile, None, store)?;
    client.set_nonblocking()?;
    let (mut listener, _) = client
        .session_mut()
        .channel_forward_listen(tunnel.bind_port, Some(&tunnel.bind_host), None)
        .map_err(|error| format!("Could not request remote forwarding: {error}"))?;
    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok(channel) => {
                let target_host = tunnel.target_host.clone();
                let target_port = tunnel.target_port;
                let running = running.clone();
                thread::spawn(move || {
                    let result = TcpStream::connect((target_host.as_str(), target_port))
                        .map_err(|error| format!("Could not reach local tunnel target: {error}"))
                        .and_then(|socket| pump(channel, socket, &running));
                    if let Err(error) = result {
                        eprintln!("Serverbox remote tunnel connection failed: {error}");
                    }
                });
            }
            Err(error) if error.code() == ssh2::ErrorCode::Session(-37) => {
                thread::sleep(Duration::from_millis(40))
            }
            Err(error) => return Err(format!("Remote tunnel failed: {error}")),
        }
    }
    Ok(())
}

fn pump(
    mut channel: ssh2::Channel,
    mut socket: TcpStream,
    running: &Arc<AtomicBool>,
) -> Result<(), String> {
    socket.set_read_timeout(None).ok();
    socket.set_write_timeout(None).ok();
    socket
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let mut net_buffer = [0u8; 32 * 1024];
    let mut ssh_buffer = [0u8; 32 * 1024];
    let mut to_ssh = Vec::new();
    let mut to_socket = Vec::new();
    let mut socket_eof = false;
    while running.load(Ordering::SeqCst) && (!channel.eof() || !to_socket.is_empty()) {
        let mut progressed = false;
        if !socket_eof && to_ssh.len() < 256 * 1024 {
            match socket.read(&mut net_buffer) {
                Ok(0) => socket_eof = true,
                Ok(size) => {
                    to_ssh.extend_from_slice(&net_buffer[..size]);
                    progressed = true;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(format!("Tunnel socket read failed: {error}")),
            }
        }
        if !to_ssh.is_empty() {
            match channel.write(&to_ssh) {
                Ok(size) => {
                    to_ssh.drain(..size);
                    progressed = true;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(format!("Tunnel SSH write failed: {error}")),
            }
        }
        if socket_eof && to_ssh.is_empty() {
            let _ = channel.send_eof();
        }
        if !channel.eof() && to_socket.len() < 256 * 1024 {
            match channel.read(&mut ssh_buffer) {
                Ok(0) => {}
                Ok(size) => {
                    to_socket.extend_from_slice(&ssh_buffer[..size]);
                    progressed = true;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(format!("Tunnel SSH read failed: {error}")),
            }
        }
        if !to_socket.is_empty() {
            match socket.write(&to_socket) {
                Ok(size) => {
                    to_socket.drain(..size);
                    progressed = true;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(format!("Tunnel socket write failed: {error}")),
            }
        }
        if !progressed {
            thread::sleep(Duration::from_millis(4));
        }
    }
    let _ = channel.close();
    Ok(())
}

/// SOCKS5 listeners accept connections without authentication, so they must
/// never be reachable from other machines. Restrict them to loopback binds;
/// local/remote forwarding keeps the explicit-override behavior (the frontend
/// confirms non-loopback binds at save time).
fn loopback_bind_addresses(bind_host: &str, bind_port: u16) -> Result<Vec<SocketAddr>, String> {
    let addresses = match bind_host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, bind_port)],
        Err(_) => (bind_host, bind_port)
            .to_socket_addrs()
            .map_err(|error| format!("Could not resolve tunnel bind host {bind_host}: {error}"))?
            .collect::<Vec<_>>(),
    };
    if addresses.is_empty() {
        return Err(format!(
            "Tunnel bind host {bind_host} did not resolve to an address"
        ));
    }
    if addresses.iter().any(|address| !address.ip().is_loopback()) {
        return Err(format!(
            "SOCKS5 proxies must bind to a loopback address (127.0.0.1 or ::1). Binding {bind_host} would expose an unauthenticated proxy to other machines."
        ));
    }
    Ok(addresses)
}

fn socks_target(stream: &mut TcpStream) -> Result<(String, u16), String> {
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut hello = [0u8; 2];
    stream
        .read_exact(&mut hello)
        .map_err(|error| error.to_string())?;
    if hello[0] != 5 {
        return Err("Only SOCKS5 is supported".to_string());
    }
    let mut methods = vec![0; hello[1] as usize];
    stream
        .read_exact(&mut methods)
        .map_err(|error| error.to_string())?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).ok();
        return Err("SOCKS client requires authentication".to_string());
    }
    stream
        .write_all(&[5, 0])
        .map_err(|error| error.to_string())?;
    let mut request = [0u8; 4];
    stream
        .read_exact(&mut request)
        .map_err(|error| error.to_string())?;
    if request[1] != 1 {
        return Err("Only SOCKS CONNECT is supported".to_string());
    }
    let host = match request[3] {
        1 => {
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).map_err(|e| e.to_string())?;
            IpAddr::V4(Ipv4Addr::from(bytes)).to_string()
        }
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).map_err(|e| e.to_string())?;
            let mut bytes = vec![0; length[0] as usize];
            stream.read_exact(&mut bytes).map_err(|e| e.to_string())?;
            String::from_utf8(bytes).map_err(|_| "Invalid SOCKS host".to_string())?
        }
        4 => {
            let mut bytes = [0u8; 16];
            stream.read_exact(&mut bytes).map_err(|e| e.to_string())?;
            IpAddr::V6(Ipv6Addr::from(bytes)).to_string()
        }
        _ => return Err("Invalid SOCKS address".to_string()),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).map_err(|e| e.to_string())?;
    Ok((host, u16::from_be_bytes(port)))
}
