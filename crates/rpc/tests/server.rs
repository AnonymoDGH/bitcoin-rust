mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use btc_rpc::{serve_listener, RpcBackend};
use common::MockBackend;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Base64 of `user:pass`.
const AUTH: &str = "Basic dXNlcjpwYXNz";

async fn start(auth: Option<(&str, &str)>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let backend: Arc<dyn RpcBackend> = Arc::new(MockBackend::new());
    let auth = auth.map(|(user, pass)| (user.to_owned(), pass.to_owned()));
    tokio::spawn(serve_listener(listener, auth, backend));
    addr
}

async fn connect(addr: SocketAddr) -> BufReader<TcpStream> {
    BufReader::new(TcpStream::connect(addr).await.unwrap())
}

fn post(auth: Option<&str>, body: &str) -> Vec<u8> {
    request("POST", auth, body, "")
}

fn request(method: &str, auth: Option<&str>, body: &str, extra_headers: &str) -> Vec<u8> {
    let mut text = format!("{method} / HTTP/1.1\r\nHost: localhost\r\n");
    if let Some(auth) = auth {
        text.push_str(&format!("Authorization: {auth}\r\n"));
    }
    text.push_str(extra_headers);
    text.push_str(&format!(
        "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    ));
    text.into_bytes()
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("reply body is JSON")
    }
}

async fn send(reader: &mut BufReader<TcpStream>, bytes: &[u8]) -> Reply {
    reader.get_mut().write_all(bytes).await.unwrap();
    read_reply(reader).await
}

async fn read_reply(reader: &mut BufReader<TcpStream>) -> Reply {
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await.unwrap();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map_or(0, |(_, value)| value.parse::<usize>().unwrap());
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await.unwrap();
    Reply {
        status,
        headers,
        body,
    }
}

#[tokio::test]
async fn authorized_request_returns_json_result() {
    let addr = start(Some(("user", "pass"))).await;
    let mut conn = connect(addr).await;
    let reply = send(
        &mut conn,
        &post(Some(AUTH), r#"{"method":"getblockcount","id":1}"#),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    let body = reply.json();
    assert_eq!(body["result"], 2);
    assert_eq!(body["id"], 1);
}

#[tokio::test]
async fn wrong_password_is_rejected_with_challenge() {
    let addr = start(Some(("user", "pass"))).await;
    let mut conn = connect(addr).await;
    let reply = send(
        &mut conn,
        &post(Some("Basic dXNlcjp4eHg="), r#"{"method":"getblockcount"}"#),
    )
    .await;
    assert_eq!(reply.status, 401);
    assert_eq!(
        reply.header("www-authenticate"),
        Some("Basic realm=\"jsonrpc\"")
    );
    assert!(reply.body.is_empty());
}

#[tokio::test]
async fn missing_authorization_is_rejected() {
    let addr = start(Some(("user", "pass"))).await;
    let mut conn = connect(addr).await;
    let reply = send(&mut conn, &post(None, r#"{"method":"getblockcount"}"#)).await;
    assert_eq!(reply.status, 401);
}

#[tokio::test]
async fn no_auth_configured_accepts_anonymous_requests() {
    let addr = start(None).await;
    let mut conn = connect(addr).await;
    let reply = send(
        &mut conn,
        &post(None, r#"{"method":"getblockcount","id":2}"#),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["result"], 2);
}

#[tokio::test]
async fn non_post_methods_are_rejected() {
    let addr = start(None).await;
    let mut conn = connect(addr).await;
    let reply = send(&mut conn, &request("GET", None, "", "")).await;
    assert_eq!(reply.status, 405);
    assert_eq!(reply.body, b"JSONRPC server handles only POST requests\n");
}

#[tokio::test]
async fn method_not_found_is_404_for_v1_and_200_for_v2() {
    let addr = start(None).await;
    let mut conn = connect(addr).await;

    let v1 = send(&mut conn, &post(None, r#"{"method":"nope","id":1}"#)).await;
    assert_eq!(v1.status, 404);
    assert_eq!(v1.json()["error"]["code"], -32601);
    assert!(v1.json()["result"].is_null());

    let v2 = send(
        &mut conn,
        &post(None, r#"{"jsonrpc":"2.0","method":"nope","id":2}"#),
    )
    .await;
    assert_eq!(v2.status, 200);
    assert_eq!(v2.json()["error"]["code"], -32601);
    assert_eq!(v2.json()["id"], 2);
}

#[tokio::test]
async fn v1_execution_error_is_500_with_error_body() {
    let addr = start(None).await;
    let mut conn = connect(addr).await;
    let reply = send(
        &mut conn,
        &post(None, r#"{"method":"getblockhash","params":[99],"id":3}"#),
    )
    .await;
    assert_eq!(reply.status, 500);
    assert_eq!(reply.json()["error"]["code"], -8);
    assert_eq!(reply.json()["id"], 3);
}

#[tokio::test]
async fn malformed_json_is_a_parse_error() {
    let addr = start(None).await;
    let mut conn = connect(addr).await;
    let reply = send(&mut conn, &post(None, "{not json")).await;
    assert_eq!(reply.status, 500);
    assert_eq!(reply.json()["error"]["code"], -32700);
    assert!(reply.json().get("id").is_none());
}

#[tokio::test]
async fn notification_gets_204_and_connection_stays_open() {
    let addr = start(None).await;
    let mut conn = connect(addr).await;
    let reply = send(
        &mut conn,
        &post(None, r#"{"jsonrpc":"2.0","method":"getblockcount"}"#),
    )
    .await;
    assert_eq!(reply.status, 204);
    assert!(reply.body.is_empty());
    assert!(reply.header("content-length").is_none());

    let next = send(
        &mut conn,
        &post(None, r#"{"method":"getblockcount","id":4}"#),
    )
    .await;
    assert_eq!(next.json()["result"], 2);
}

#[tokio::test]
async fn keep_alive_serves_several_requests_on_one_connection() {
    let addr = start(Some(("user", "pass"))).await;
    let mut conn = connect(addr).await;
    for id in 0..3 {
        let body = format!(r#"{{"method":"getblockhash","params":[{id}],"id":{id}}}"#);
        let reply = send(&mut conn, &post(Some(AUTH), &body)).await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.json()["id"], id);
        assert!(reply.json()["result"].is_string());
    }
}

#[tokio::test]
async fn connection_close_header_closes_the_socket() {
    let addr = start(None).await;
    let mut conn = connect(addr).await;
    let reply = send(
        &mut conn,
        &request(
            "POST",
            None,
            r#"{"method":"getblockcount"}"#,
            "Connection: close\r\n",
        ),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("connection"), Some("close"));
    let mut rest = Vec::new();
    conn.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
}

#[tokio::test]
async fn batch_over_http_returns_array() {
    let addr = start(None).await;
    let mut conn = connect(addr).await;
    let body = json!([
        { "method": "getblockcount", "id": "a" },
        { "method": "getbestblockhash", "id": "b" }
    ])
    .to_string();
    let reply = send(&mut conn, &post(None, &body)).await;
    assert_eq!(reply.status, 200);
    let items = reply.json();
    assert_eq!(items[0]["id"], "a");
    assert_eq!(items[0]["result"], 2);
    assert_eq!(items[1]["id"], "b");
    assert!(items[1]["result"].is_string());
}
