use crate::models::{TerminalEvent, TerminalRequest, TerminalResize, TerminalStarted};
use crate::ssh::{begin_operation, finish_operation, SshClient, KEEPALIVE_INTERVAL_SECONDS};
use crate::storage::Store;
use ssh2::{ErrorCode, ExtendedData};
use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use uuid::Uuid;

#[derive(Debug)]
pub enum TerminalCommand {
    Input(Vec<u8>),
    Resize(u32, u32),
    Close,
}

const MAX_PENDING_INPUT_BYTES: usize = 1024 * 1024;
const MAX_KEEPALIVE_FAILURES: u8 = 3;
const KEEPALIVE_RETRY_DELAY: Duration = Duration::from_secs(1);
const TERMINAL_POLL_INTERVAL: Duration = Duration::from_millis(12);

#[derive(Clone)]
pub struct TerminalSession {
    server_id: String,
    sender: mpsc::Sender<TerminalCommand>,
    pending_input_bytes: Arc<AtomicUsize>,
}

pub type TerminalSessions = Arc<Mutex<HashMap<String, TerminalSession>>>;

pub fn start(
    app: AppHandle,
    store: Store,
    sessions: TerminalSessions,
    request: TerminalRequest,
    operation_id: Option<&str>,
) -> Result<TerminalStarted, String> {
    let session_id = Uuid::parse_str(&request.session_id)
        .map_err(|_| "Invalid terminal session identifier".to_string())?
        .to_string();
    let (sender, receiver) = mpsc::channel();
    let pending_input_bytes = Arc::new(AtomicUsize::new(0));
    let profile = store.get_server(&request.server_id)?;
    let operation = begin_operation(operation_id);
    let cancellation = operation.as_ref().map(|operation| operation.cancellation());
    let mut client =
        match SshClient::connect_with_cancellation(&profile, cancellation.as_ref(), &store) {
            Ok(client) => client,
            Err(error) => {
                finish_operation(operation);
                return Err(error);
            }
        };
    let mut channel = match client.open_channel() {
        Ok(channel) => channel,
        Err(error) => {
            finish_operation(operation);
            return Err(error);
        }
    };
    if let Some(cancellation) = cancellation.as_ref() {
        if cancellation.load(std::sync::atomic::Ordering::SeqCst) {
            finish_operation(operation);
            return Err(crate::ssh::OPERATION_CANCELLED.to_string());
        }
    }
    if let Err(error) =
        SshClient::request_pty(&mut channel, request.cols.max(20), request.rows.max(5))
    {
        finish_operation(operation);
        return Err(error);
    }
    let command = request.command.filter(|value| !value.trim().is_empty());
    let channel_start = if let Some(command) = command.as_deref() {
        channel
            .exec(command)
            .map_err(|error| format!("Could not start the remote command: {error}"))
    } else {
        channel
            .shell()
            .map_err(|error| format!("Could not start the remote shell: {error}"))
    };
    if let Err(error) = channel_start {
        finish_operation(operation);
        return Err(error);
    }
    if let Err(error) = channel
        .handle_extended_data(ExtendedData::Merge)
        .map_err(|error| format!("Could not prepare terminal output: {error}"))
    {
        finish_operation(operation);
        return Err(error);
    }
    client
        .session_mut()
        .set_keepalive(true, KEEPALIVE_INTERVAL_SECONDS);
    if let Err(error) = client.set_nonblocking() {
        finish_operation(operation);
        return Err(error);
    }
    if let Err(error) = sessions
        .lock()
        .map_err(|_| "Terminal session lock was poisoned".to_string())
        .map(|mut sessions| {
            sessions.insert(
                session_id.clone(),
                TerminalSession {
                    server_id: request.server_id.clone(),
                    sender,
                    pending_input_bytes: pending_input_bytes.clone(),
                },
            )
        })
    {
        finish_operation(operation);
        return Err(error);
    }
    if cancellation
        .as_ref()
        .is_some_and(|value| value.load(std::sync::atomic::Ordering::SeqCst))
    {
        if let Ok(mut sessions) = sessions.lock() {
            sessions.remove(&session_id);
        }
        let _ = channel.close();
        finish_operation(operation);
        return Err(crate::ssh::OPERATION_CANCELLED.to_string());
    }
    finish_operation(operation);

    let thread_session_id = session_id.clone();
    let thread_sessions = sessions.clone();
    thread::spawn(move || {
        let mut buffer = [0u8; 16 * 1024];
        let mut pending_input = VecDeque::<(Vec<u8>, usize)>::new();
        let mut pending_resize = None;
        let mut retrying_input_write = false;
        let mut stdout_utf8 = Vec::new();
        let mut next_keepalive =
            Instant::now() + Duration::from_secs(KEEPALIVE_INTERVAL_SECONDS.into());
        let mut keepalive_failures = 0u8;
        let mut closed = false;
        let mut close_message = None;
        while !closed {
            while let Ok(command) = receiver.try_recv() {
                match command {
                    TerminalCommand::Input(data) => {
                        if !data.is_empty() {
                            pending_input.push_back((data, 0));
                        }
                    }
                    TerminalCommand::Resize(cols, rows) => {
                        pending_resize = Some((cols.max(20), rows.max(5)));
                    }
                    TerminalCommand::Close => {
                        closed = true;
                        break;
                    }
                }
            }
            if closed {
                break;
            }
            if !retrying_input_write {
                if let Some((cols, rows)) = pending_resize {
                    match channel.request_pty_size(cols, rows, None, None) {
                        Ok(()) => pending_resize = None,
                        Err(error) if retryable_ssh_error(&error) => {
                            thread::sleep(TERMINAL_POLL_INTERVAL);
                            continue;
                        }
                        Err(error) => {
                            close_message =
                                Some(format!("Terminal connection lost while resizing: {error}"));
                            closed = true;
                        }
                    }
                }
            }
            if closed {
                break;
            }
            if let Some((data, offset)) = pending_input.front_mut() {
                match channel.write(&data[*offset..]) {
                    Ok(size) if size > 0 => {
                        retrying_input_write = false;
                        *offset += size;
                        pending_input_bytes.fetch_sub(size, Ordering::Relaxed);
                        if *offset == data.len() {
                            pending_input.pop_front();
                        }
                    }
                    Ok(_) => {
                        retrying_input_write = true;
                        thread::sleep(TERMINAL_POLL_INTERVAL);
                        continue;
                    }
                    Err(error) if retryable_io_error(&error) => {
                        retrying_input_write = true;
                        thread::sleep(TERMINAL_POLL_INTERVAL);
                        continue;
                    }
                    Err(error) => {
                        close_message = Some(format!(
                            "Terminal connection lost while sending input: {error}"
                        ));
                        closed = true;
                    }
                }
            }
            if closed {
                break;
            }
            match channel.read(&mut buffer) {
                Ok(size) if size > 0 => {
                    emit_utf8_data(&app, &thread_session_id, &mut stdout_utf8, &buffer[..size])
                }
                Err(error) if retryable_io_error(&error) => {}
                Err(error) => {
                    close_message = Some(format!(
                        "Terminal connection lost while reading output: {error}"
                    ));
                    closed = true;
                }
                _ => {}
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
                            close_message = Some(format!("SSH connection lost: {error}"));
                            closed = true;
                        } else {
                            next_keepalive = Instant::now() + KEEPALIVE_RETRY_DELAY;
                        }
                    }
                }
            }
            if channel.eof() {
                closed = true;
            }
            if !closed {
                thread::sleep(TERMINAL_POLL_INTERVAL);
            }
        }
        flush_utf8_data(&app, &thread_session_id, &mut stdout_utf8);
        let exit_status = command.as_ref().and_then(|_| channel.exit_status().ok());
        let _ = channel.close();
        let _ = channel.wait_close();
        let _ = thread_sessions
            .lock()
            .map(|mut sessions| sessions.remove(&thread_session_id));
        let _ = app.emit(
            "terminal-closed",
            TerminalEvent {
                session_id: thread_session_id,
                data: close_message.unwrap_or_else(|| match exit_status {
                    Some(0) => "Remote command finished".to_string(),
                    Some(status) => format!("Remote command exited with status {status}"),
                    None => "Remote shell exited".to_string(),
                }),
            },
        );
    });
    Ok(TerminalStarted {
        session_id,
        server_id: profile.id,
    })
}

pub fn input(sessions: &TerminalSessions, session_id: &str, data: String) -> Result<(), String> {
    let session = sessions
        .lock()
        .map_err(|_| "Terminal session lock was poisoned".to_string())?
        .get(session_id)
        .cloned()
        .ok_or_else(|| "That terminal session is no longer connected".to_string())?;
    let data = data.into_bytes();
    let length = data.len();
    reserve_input_bytes(&session.pending_input_bytes, length)?;
    session
        .sender
        .send(TerminalCommand::Input(data))
        .map_err(|_| {
            session
                .pending_input_bytes
                .fetch_sub(length, Ordering::Relaxed);
            "That terminal session is no longer connected".to_string()
        })
}

pub fn resize(sessions: &TerminalSessions, request: TerminalResize) -> Result<(), String> {
    let sender = sessions
        .lock()
        .map_err(|_| "Terminal session lock was poisoned".to_string())?
        .get(&request.session_id)
        .map(|session| session.sender.clone())
        .ok_or_else(|| "That terminal session is no longer connected".to_string())?;
    sender
        .send(TerminalCommand::Resize(request.cols, request.rows))
        .map_err(|_| "That terminal session is no longer connected".to_string())
}

pub fn close(sessions: &TerminalSessions, session_id: &str) -> Result<(), String> {
    if let Some(sender) = sessions
        .lock()
        .map_err(|_| "Terminal session lock was poisoned".to_string())?
        .get(session_id)
        .map(|session| session.sender.clone())
    {
        let _ = sender.send(TerminalCommand::Close);
    }
    Ok(())
}

pub fn close_server(sessions: &TerminalSessions, server_id: &str) {
    let senders = sessions
        .lock()
        .map(|mut sessions| {
            let session_ids = sessions
                .iter()
                .filter(|(_, session)| session.server_id == server_id)
                .map(|(session_id, _)| session_id.clone())
                .collect::<Vec<_>>();
            session_ids
                .into_iter()
                .filter_map(|session_id| sessions.remove(&session_id))
                .map(|session| session.sender)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for sender in senders {
        let _ = sender.send(TerminalCommand::Close);
    }
}

pub fn close_all(sessions: &TerminalSessions) {
    let senders = sessions
        .lock()
        .map(|mut sessions| {
            sessions
                .drain()
                .map(|(_, session)| session.sender)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for sender in senders {
        let _ = sender.send(TerminalCommand::Close);
    }
}

fn retryable_io_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::WouldBlock | ErrorKind::Interrupted | ErrorKind::TimedOut
    )
}

fn retryable_ssh_error(error: &ssh2::Error) -> bool {
    matches!(
        error.code(),
        ErrorCode::Session(-37) | ErrorCode::Session(-9)
    )
}

fn reserve_input_bytes(pending: &AtomicUsize, length: usize) -> Result<(), String> {
    let mut current = pending.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(length) else {
            return Err(
                "Terminal input queue is full; wait for the remote host to catch up".to_string(),
            );
        };
        if next > MAX_PENDING_INPUT_BYTES {
            return Err(
                "Terminal input queue is full; wait for the remote host to catch up".to_string(),
            );
        }
        match pending.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(()),
            Err(value) => current = value,
        }
    }
}

fn emit_utf8_data(app: &AppHandle, session_id: &str, pending: &mut Vec<u8>, data: &[u8]) {
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
        emit_data(app, session_id, output);
    }
}

fn flush_utf8_data(app: &AppHandle, session_id: &str, pending: &mut Vec<u8>) {
    if !pending.is_empty() {
        let output = String::from_utf8_lossy(pending).into_owned();
        pending.clear();
        emit_data(app, session_id, output);
    }
}

fn emit_data(app: &AppHandle, session_id: &str, data: String) {
    let _ = app.emit(
        "terminal-output",
        TerminalEvent {
            session_id: session_id.to_string(),
            data,
        },
    );
}
