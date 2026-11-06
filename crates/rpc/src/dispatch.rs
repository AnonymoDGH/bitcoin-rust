//! JSON-RPC 1.0 and 2.0 envelope handling: request parsing, single and batch
//! execution, and reply shapes (`JSONRPCRequest::parse`, `JSONRPCReplyObj` and
//! `ExecuteHTTPRPC` in Core).

use serde_json::{json, Map, Value};

use crate::backend::RpcBackend;
use crate::error::{
    RpcError, RpcResult, RPC_INVALID_REQUEST, RPC_METHOD_NOT_FOUND, RPC_PARSE_ERROR,
};
use crate::methods;
use crate::params::{normalize, Args};

/// Executes one JSON-RPC request or batch and returns the reply.
///
/// Returns `Value::Null` when there is nothing to send back: a JSON-RPC 2.0
/// notification, or a batch made only of notifications.
pub fn dispatch(backend: &dyn RpcBackend, req: Value) -> Value {
    handle(backend, req).1
}

/// Like [`dispatch`], also returning the HTTP status Core would use.
pub(crate) fn handle(backend: &dyn RpcBackend, req: Value) -> (u16, Value) {
    match req {
        Value::Array(items) => batch(backend, &items),
        Value::Object(_) => single(backend, &req),
        _ => error_reply(
            Version::V1,
            None,
            RpcError::new(RPC_PARSE_ERROR, "Top-level object parse error"),
        ),
    }
}

/// Reply for a body that is not valid JSON.
pub(crate) fn parse_error() -> (u16, Value) {
    error_reply(
        Version::V1,
        None,
        RpcError::new(RPC_PARSE_ERROR, "Parse error"),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Version {
    V1,
    V2,
}

struct Call {
    id: Option<Value>,
    version: Version,
    method: String,
    params: Value,
}

impl Call {
    fn is_notification(&self) -> bool {
        self.version == Version::V2 && self.id.is_none()
    }
}

struct Rejected {
    id: Option<Value>,
    version: Version,
    error: RpcError,
}

fn single(backend: &dyn RpcBackend, req: &Value) -> (u16, Value) {
    let call = match parse(req) {
        Ok(call) => call,
        Err(rejected) => return error_reply(rejected.version, rejected.id, rejected.error),
    };
    if call.is_notification() {
        let _ = execute(backend, &call);
        return (204, Value::Null);
    }
    let version = call.version;
    let result = execute(backend, &call);
    let status = match (&result, version) {
        (Err(error), Version::V1) => status_for(error.code),
        _ => 200,
    };
    (status, reply(version, call.id, result))
}

fn batch(backend: &dyn RpcBackend, items: &[Value]) -> (u16, Value) {
    let mut replies = Vec::new();
    for item in items {
        match parse(item) {
            Ok(call) if call.is_notification() => {
                let _ = execute(backend, &call);
            }
            Ok(call) => {
                let result = execute(backend, &call);
                replies.push(reply(call.version, call.id, result));
            }
            Err(rejected) => {
                replies.push(reply(rejected.version, rejected.id, Err(rejected.error)))
            }
        }
    }
    if replies.is_empty() && !items.is_empty() {
        return (204, Value::Null);
    }
    (200, Value::Array(replies))
}

fn parse(req: &Value) -> Result<Call, Rejected> {
    let Some(obj) = req.as_object() else {
        return Err(rejected(
            None,
            Version::V1,
            RPC_INVALID_REQUEST,
            "Invalid Request object",
        ));
    };
    let id = obj.get("id").cloned();
    let mut version = Version::V1;
    match obj.get("jsonrpc") {
        None | Some(Value::Null) => {}
        Some(Value::String(v)) if v == "1.0" => {}
        Some(Value::String(v)) if v == "2.0" => version = Version::V2,
        Some(Value::String(_)) => {
            return Err(rejected(
                id,
                version,
                RPC_INVALID_REQUEST,
                "JSON-RPC version not supported",
            ))
        }
        Some(_) => {
            return Err(rejected(
                id,
                version,
                RPC_INVALID_REQUEST,
                "jsonrpc field must be a string",
            ))
        }
    }
    let method = match obj.get("method") {
        None | Some(Value::Null) => {
            return Err(rejected(id, version, RPC_INVALID_REQUEST, "Missing method"));
        }
        Some(Value::String(method)) => method.clone(),
        Some(_) => {
            return Err(rejected(
                id,
                version,
                RPC_INVALID_REQUEST,
                "Method must be a string",
            ))
        }
    };
    let params = match obj.get("params") {
        None | Some(Value::Null) => Value::Array(Vec::new()),
        Some(params @ (Value::Array(_) | Value::Object(_))) => params.clone(),
        Some(_) => {
            return Err(rejected(
                id,
                version,
                RPC_INVALID_REQUEST,
                "Params must be an array or object",
            ));
        }
    };
    Ok(Call {
        id,
        version,
        method,
        params,
    })
}

fn rejected(id: Option<Value>, version: Version, code: i32, message: &str) -> Rejected {
    Rejected {
        id,
        version,
        error: RpcError::new(code, message),
    }
}

fn execute(backend: &dyn RpcBackend, call: &Call) -> RpcResult<Value> {
    let method = methods::lookup(&call.method)
        .ok_or_else(|| RpcError::new(RPC_METHOD_NOT_FOUND, "Method not found"))?;
    let positional = normalize(method.params, &call.params)?;
    methods::call(backend, method.name, &Args::new(positional))
}

fn reply(version: Version, id: Option<Value>, result: RpcResult<Value>) -> Value {
    let mut m = Map::new();
    if version == Version::V2 {
        m.insert("jsonrpc".into(), json!("2.0"));
    }
    match result {
        Ok(value) => {
            m.insert("result".into(), value);
            if version == Version::V1 {
                m.insert("error".into(), Value::Null);
            }
        }
        Err(error) => {
            if version == Version::V1 {
                m.insert("result".into(), Value::Null);
            }
            m.insert(
                "error".into(),
                json!({ "code": error.code, "message": error.message }),
            );
        }
    }
    if let Some(id) = id {
        m.insert("id".into(), id);
    }
    Value::Object(m)
}

fn error_reply(version: Version, id: Option<Value>, error: RpcError) -> (u16, Value) {
    (status_for(error.code), reply(version, id, Err(error)))
}

/// HTTP status Core uses for a top-level JSON-RPC error.
fn status_for(code: i32) -> u16 {
    match code {
        RPC_INVALID_REQUEST => 400,
        RPC_METHOD_NOT_FOUND => 404,
        _ => 500,
    }
}
