use crate::models::{LogStreamEvent, LogStreamRequest, LogStreamStarted};
use crate::providers;
use crate::ssh::{
    command_error, is_permission_error, quote_shell, sudo_password_input, validate_sudo_password,
    SshClient, KEEPALIVE_INTERVAL_SECONDS,
};
use crate::storage::Store;
use ssh2::{ErrorCode, ExtendedData};
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use uuid::Uuid;
use zeroize::Zeroizing;

const STREAM_POLL_INTERVAL: Duration = Duration::from_millis(20);
const KEEPALIVE_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_KEEPALIVE_FAILURES: u8 = 3;
const ACCESS_STATUS_MARKER: &str = "__SERVERBOX_LOG_ACCESS_STATUS__";
const UID_MARKER: &str = "__SERVERBOX_LOG_UID__";
const PASSWORDLESS_SUDO_MARKER: &str = "__SERVERBOX_LOG_PASSWORDLESS_SUDO__";

#[derive(Clone)]
pub struct LogSession {
    server_id: String,
    close: mpsc::Sender<()>,
}

pub type LogSessions = Arc<Mutex<HashMap<String, LogSession>>>;

pub fn start(
    app: AppHandle,
    store: Store,
    sessions: LogSessions,
    request: LogStreamRequest,
) -> Result<LogStreamStarted, String> {
    let session_id = Uuid::parse_str(&request.session_id)
        .map_err(|_| "Invalid log stream identifier".to_string())?
        .to_string();
    let profile = store.get_server(&request.server_id)?;
    let mut client = SshClient::connect_with_cancellation(&profile, None, &store)?;
    let direct_command =
        providers::log_command(&mut client, &profile, &store, &request.logs, true)?;
    let access_command =
        providers::log_access_command(&mut client, &profile, &store, &request.logs)?;
    let probe_command = format!(
        "( {access_command} ); access_status=$?; printf '\\n{ACCESS_STATUS_MARKER}\\t%s\\n' \"$access_status\"; printf '{UID_MARKER}\\t%s\\n' \"$(id -u 2>/dev/null)\"; if sudo -n true >/dev/null 2>&1; then printf '{PASSWORDLESS_SUDO_MARKER}\\ttrue\\n'; else printf '{PASSWORDLESS_SUDO_MARKER}\\tfalse\\n'; fi"
    );
    let access = client.exec(&probe_command)?;
    let access_status = probe_value(&access.stdout, ACCESS_STATUS_MARKER)
        .and_then(|value| value.parse::<i32>().ok())
        .ok_or_else(|| "The server returned an invalid live-log access probe".to_string())?;
    let mut sudo_password = None;
    let command = if access_status == 0 {
        direct_command
    } else if is_permission_error(&access) {
        if probe_value(&access.stdout, UID_MARKER) == Some("0") {
            direct_command
        } else if probe_value(&access.stdout, PASSWORDLESS_SUDO_MARKER) == Some("true") {
            format!("sudo -n sh -c {}", quote_shell(&direct_command))
        } else {
            let password =
                Zeroizing::new(store.get_secret(&profile.id, "sudo-password")?.ok_or_else(
                    || {
                        "Live logs need sudo. Add a sudo password to the server connection first."
                            .to_string()
                    },
                )?);
            validate_sudo_password(&mut client, &password)?;
            sudo_password = Some(password);
            format!(
                "LC_ALL=C sudo -S -k -p '' sh -c {}",
                quote_shell(&direct_command)
            )
        }
    } else {
        return Err(command_error(&access));
    };
    let mut channel = client.open_channel()?;
    channel
        .exec(&command)
        .map_err(|error| format!("Could not start live logs: {error}"))?;
    if let Some(password) = sudo_password.as_ref() {
        let input = sudo_password_input(&password, &[]);
        channel
            .write_all(input.as_slice())
            .map_err(|error| format!("Could not send the sudo password for live logs: {error}"))?;
        channel
            .send_eof()
            .map_err(|error| format!("Could not finish live-log authentication: {error}"))?;
    }
    channel
        .handle_extended_data(ExtendedData::Merge)
        .map_err(|error| format!("Could not prepare live log output: {error}"))?;
    client
        .session_mut()
        .set_keepalive(true, KEEPALIVE_INTERVAL_SECONDS);
    client.set_nonblocking()?;

    let (close, close_receiver) = mpsc::channel();
    sessions
        .lock()
        .map_err(|_| "Log stream lock was poisoned".to_string())?
        .insert(
            session_id.clone(),
            LogSession {
                server_id: request.server_id.clone(),
                close,
            },
        );

    let thread_session_id = session_id.clone();
    let thread_sessions = sessions.clone();
    thread::spawn(move || {
        let mut buffer = [0_u8; 16 * 1024];
        let mut pending_utf8 = Vec::new();
        let mut next_keepalive =
            Instant::now() + Duration::from_secs(KEEPALIVE_INTERVAL_SECONDS.into());
        let mut keepalive_failures = 0_u8;
        let mut close_message = None;
        loop {
            if close_receiver.try_recv().is_ok() {
                break;
            }
            match channel.read(&mut buffer) {
                Ok(size) if size > 0 => {
                    emit_utf8(&app, &thread_session_id, &mut pending_utf8, &buffer[..size])
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::WouldBlock | ErrorKind::Interrupted | ErrorKind::TimedOut
                    ) => {}
                Err(error) => {
                    close_message = Some(format!("Live log connection lost: {error}"));
                    break;
                }
                _ => {}
            }
            if channel.eof() {
                break;
            }
            if Instant::now() >= next_keepalive {
                match client.session_mut().keepalive_send() {
                    Ok(seconds) => {
                        keepalive_failures = 0;
                        next_keepalive =
                            Instant::now() + Duration::from_secs(u64::from(seconds.max(1)));
                    }
                    Err(error) if error.code() == ErrorCode::Session(-37) => {
                        next_keepalive = Instant::now() + Duration::from_millis(250);
                    }
                    Err(error) => {
                        keepalive_failures += 1;
                        if keepalive_failures >= MAX_KEEPALIVE_FAILURES {
                            close_message = Some(format!("Live log connection lost: {error}"));
                            break;
                        }
                        next_keepalive = Instant::now() + KEEPALIVE_RETRY_DELAY;
                    }
                }
            }
            thread::sleep(STREAM_POLL_INTERVAL);
        }
        flush_utf8(&app, &thread_session_id, &mut pending_utf8);
        let exit_status = channel.exit_status().ok();
        let _ = channel.close();
        let _ = channel.wait_close();
        let _ = thread_sessions
            .lock()
            .map(|mut values| values.remove(&thread_session_id));
        let message = close_message.unwrap_or_else(|| match exit_status {
            Some(0) | None => "Live log stream stopped".to_string(),
            Some(status) => format!("Live log command exited with status {status}"),
        });
        let _ = app.emit(
            "log-stream-closed",
            LogStreamEvent {
                session_id: thread_session_id,
                data: message,
            },
        );
    });

    Ok(LogStreamStarted {
        session_id,
        server_id: request.server_id,
    })
}

fn probe_value<'a>(output: &'a str, marker: &str) -> Option<&'a str> {
    output
        .lines()
        .find_map(|line| line.strip_prefix(marker)?.strip_prefix('\t'))
}

pub fn close(sessions: &LogSessions, session_id: &str) -> Result<(), String> {
    if let Some(sender) = sessions
        .lock()
        .map_err(|_| "Log stream lock was poisoned".to_string())?
        .get(session_id)
        .map(|session| session.close.clone())
    {
        let _ = sender.send(());
    }
    Ok(())
}

pub fn close_server(sessions: &LogSessions, server_id: &str) {
    let senders = sessions
        .lock()
        .ok()
        .map(|values| {
            values
                .values()
                .filter(|value| value.server_id == server_id)
                .map(|value| value.close.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for sender in senders {
        let _ = sender.send(());
    }
}

pub fn close_all(sessions: &LogSessions) {
    let senders = sessions
        .lock()
        .ok()
        .map(|values| {
            values
                .values()
                .map(|value| value.close.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for sender in senders {
        let _ = sender.send(());
    }
}

fn emit_utf8(app: &AppHandle, session_id: &str, pending: &mut Vec<u8>, data: &[u8]) {
    pending.extend_from_slice(data);
    let mut output = String::new();
    let mut consumed = 0;
    loop {
        match std::str::from_utf8(&pending[consumed..]) {
            Ok(valid) => {
                output.push_str(valid);
                consumed = pending.len();
                break;
            }
            Err(error) => {
                let valid_end = consumed + error.valid_up_to();
                output.push_str(
                    std::str::from_utf8(&pending[consumed..valid_end]).unwrap_or_default(),
                );
                let Some(invalid_length) = error.error_len() else {
                    consumed = valid_end;
                    break;
                };
                output.push('\u{FFFD}');
                consumed = valid_end + invalid_length;
            }
        }
    }
    pending.drain(..consumed);
    if !output.is_empty() {
        let _ = app.emit(
            "log-stream-output",
            LogStreamEvent {
                session_id: session_id.to_string(),
                data: output,
            },
        );
    }
}

fn flush_utf8(app: &AppHandle, session_id: &str, pending: &mut Vec<u8>) {
    if pending.is_empty() {
        return;
    }
    let output = String::from_utf8_lossy(pending).into_owned();
    pending.clear();
    let _ = app.emit(
        "log-stream-output",
        LogStreamEvent {
            session_id: session_id.to_string(),
            data: output,
        },
    );
}
