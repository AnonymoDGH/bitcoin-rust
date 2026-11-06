//! Minimal HTTP/1.1 server for JSON-RPC (port of the request handling in
//! `src/httpserver.cpp` and `src/httprpc.cpp`).

use std::fmt::Write as _;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::backend::RpcBackend;
use crate::dispatch::{handle, parse_error};
use crate::methods;

/// Largest accepted request body (`MAX_SIZE` in Core's `httpserver.cpp`).
const MAX_BODY: usize = 32 * 1024 * 1024;
const MAX_LINE: u64 = 8 * 1024;
const MAX_HEADERS: usize = 100;
/// Idle time allowed between requests on a connection (`-rpcservertimeout`).
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Delay after a failed login, to slow brute-force attempts.
const AUTH_FAILURE_DELAY: Duration = Duration::from_millis(250);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
const WWW_AUTHENTICATE: &str = "Basic realm=\"jsonrpc\"";

/// Binds `addr` and serves JSON-RPC until the listener fails.
///
/// With `auth` set, every request needs HTTP Basic credentials that match it.
/// With `None`, requests are accepted without credentials.
pub async fn serve(
    addr: SocketAddr,
    auth: Option<(String, String)>,
    backend: Arc<dyn RpcBackend>,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_listener(listener, auth, backend).await
}

/// Serves JSON-RPC on an already-bound listener. Accept errors are retried after
/// a short pause, so this only returns if the task is dropped.
pub async fn serve_listener(
    listener: TcpListener,
    auth: Option<(String, String)>,
    backend: Arc<dyn RpcBackend>,
) -> io::Result<()> {
    methods::start_clock();
    let auth = Arc::new(auth);
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                tokio::spawn(handle_connection(
                    stream,
                    Arc::clone(&auth),
                    Arc::clone(&backend),
                ));
            }
            Err(_) => tokio::time::sleep(ACCEPT_BACKOFF).await,
        }
    }
}

/// Failure while reading a request: either close silently or reply with a status.
enum Failure {
    Close,
    Reply(u16, &'static str),
}

struct Request {
    method: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    keep_alive: bool,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

struct Response {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl Response {
    fn text(status: u16, message: &str) -> Self {
        Self {
            status,
            headers: vec![("Content-Type", "text/plain; charset=utf-8".into())],
            body: format!("{message}\n").into_bytes(),
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    auth: Arc<Option<(String, String)>>,
    backend: Arc<dyn RpcBackend>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    loop {
        let request = match timeout(IDLE_TIMEOUT, read_request(&mut reader)).await {
            Ok(Ok(Some(request))) => request,
            Ok(Ok(None)) | Ok(Err(Failure::Close)) | Err(_) => return,
            Ok(Err(Failure::Reply(status, message))) => {
                let _ =
                    write_response(&mut write_half, &Response::text(status, message), false).await;
                return;
            }
        };
        let keep_alive = request.keep_alive;
        let response = respond(request, auth.as_ref().as_ref(), &backend).await;
        if write_response(&mut write_half, &response, keep_alive)
            .await
            .is_err()
            || !keep_alive
        {
            return;
        }
    }
}

async fn read_request(reader: &mut BufReader<OwnedReadHalf>) -> Result<Option<Request>, Failure> {
    let Some(request_line) = read_line(reader).await? else {
        return Ok(None);
    };
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(_target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(Failure::Reply(400, "Malformed request line"));
    };
    let http11 = match version {
        "HTTP/1.1" => true,
        "HTTP/1.0" => false,
        _ => return Err(Failure::Reply(400, "Unsupported HTTP version")),
    };

    let mut headers = Vec::new();
    loop {
        let line = read_line(reader).await?.ok_or(Failure::Close)?;
        if line.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(Failure::Reply(400, "Too many headers"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(Failure::Reply(400, "Malformed header"))?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }

    let request = Request {
        method: method.to_owned(),
        headers,
        body: Vec::new(),
        keep_alive: http11,
    };
    if request.header("transfer-encoding").is_some() {
        return Err(Failure::Reply(
            501,
            "Chunked request bodies are not supported",
        ));
    }
    let length = match request.header("content-length") {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| Failure::Reply(400, "Invalid Content-Length"))?,
        None => 0,
    };
    if length > MAX_BODY {
        return Err(Failure::Reply(413, "Request body too large"));
    }
    let mut body = vec![0u8; length];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| Failure::Close)?;

    let keep_alive = match request
        .header("connection")
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("close") => false,
        Some("keep-alive") => true,
        _ => http11,
    };
    Ok(Some(Request {
        body,
        keep_alive,
        ..request
    }))
}

async fn read_line(reader: &mut BufReader<OwnedReadHalf>) -> Result<Option<String>, Failure> {
    let mut line = Vec::new();
    let read = (&mut *reader)
        .take(MAX_LINE)
        .read_until(b'\n', &mut line)
        .await
        .map_err(|_| Failure::Close)?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        return Err(if read as u64 >= MAX_LINE {
            Failure::Reply(400, "Header line too long")
        } else {
            Failure::Close
        });
    }
    let text =
        String::from_utf8(line).map_err(|_| Failure::Reply(400, "Header is not valid UTF-8"))?;
    Ok(Some(text.trim_end_matches(['\r', '\n']).to_owned()))
}

async fn respond(
    request: Request,
    auth: Option<&(String, String)>,
    backend: &Arc<dyn RpcBackend>,
) -> Response {
    if request.method != "POST" {
        return Response::text(405, "JSONRPC server handles only POST requests");
    }
    if let Some(expected) = auth {
        if !authorized(request.header("authorization"), expected) {
            tokio::time::sleep(AUTH_FAILURE_DELAY).await;
            return Response {
                status: 401,
                headers: vec![("WWW-Authenticate", WWW_AUTHENTICATE.into())],
                body: Vec::new(),
            };
        }
    }

    let (status, value) = match serde_json::from_slice::<Value>(&request.body) {
        Ok(value) => {
            let backend = Arc::clone(backend);
            tokio::task::spawn_blocking(move || handle(&*backend, value))
                .await
                .unwrap_or((500, Value::Null))
        }
        Err(_) => parse_error(),
    };
    if value.is_null() {
        return Response {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        };
    }
    let mut body = serde_json::to_vec(&value).unwrap_or_default();
    body.push(b'\n');
    Response {
        status,
        headers: vec![("Content-Type", "application/json".into())],
        body,
    }
}

fn authorized(header: Option<&str>, expected: &(String, String)) -> bool {
    let Some(credentials) = header.and_then(|value| value.strip_prefix("Basic ")) else {
        return false;
    };
    let Some(decoded) = base64_decode(credentials.trim()) else {
        return false;
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((user, password)) = text.split_once(':') else {
        return false;
    };
    let user_ok = constant_time_eq(user.as_bytes(), expected.0.as_bytes());
    let password_ok = constant_time_eq(password.as_bytes(), expected.1.as_bytes());
    user_ok & password_ok
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in input.bytes() {
        if byte == b'=' {
            break;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &Response,
    keep_alive: bool,
) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n",
        response.status,
        reason(response.status)
    );
    for (name, value) in &response.headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    if response.status != 204 {
        let _ = write!(head, "Content-Length: {}\r\n", response.body.len());
    }
    head.push_str(if keep_alive {
        "Connection: keep-alive\r\n\r\n"
    } else {
        "Connection: close\r\n\r\n"
    });
    writer.write_all(head.as_bytes()).await?;
    writer.write_all(&response.body).await?;
    writer.flush().await
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decodes_basic_credentials() {
        assert_eq!(base64_decode("dXNlcjpwYXNz").unwrap(), b"user:pass");
        assert_eq!(base64_decode("dXNlcjpwYXNz=").unwrap(), b"user:pass");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert!(base64_decode("not*base64").is_none());
    }

    #[test]
    fn authorization_requires_matching_user_and_password() {
        let expected = ("user".to_owned(), "pass".to_owned());
        assert!(authorized(Some("Basic dXNlcjpwYXNz"), &expected));
        assert!(!authorized(Some("Basic dXNlcjpwYXN0"), &expected));
        assert!(!authorized(Some("Basic dXNlcjp4"), &expected));
        assert!(!authorized(Some("Bearer dXNlcjpwYXNz"), &expected));
        assert!(!authorized(None, &expected));
    }
}
