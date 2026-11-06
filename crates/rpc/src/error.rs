//! RPC error codes and the error type returned by method handlers
//! (`src/rpc/protocol.h`).

/// JSON-RPC 2.0 invalid request, mapped to HTTP 400.
pub const RPC_INVALID_REQUEST: i32 = -32600;
/// JSON-RPC 2.0 unknown method, mapped to HTTP 404.
pub const RPC_METHOD_NOT_FOUND: i32 = -32601;
/// JSON-RPC 2.0 malformed JSON.
pub const RPC_PARSE_ERROR: i32 = -32700;
/// Exception thrown while executing a command.
pub const RPC_MISC_ERROR: i32 = -1;
/// JSON value has the wrong type for a parameter.
pub const RPC_TYPE_ERROR: i32 = -3;
/// Invalid address or key.
pub const RPC_INVALID_ADDRESS_OR_KEY: i32 = -5;
/// Invalid, missing or duplicate parameter. This is Core's `RPC_INVALID_PARAMETER`
/// (-8), which the JSON-RPC 2.0 name `RPC_INVALID_PARAMS` is used for in the spec.
pub const RPC_INVALID_PARAMETER: i32 = -8;
/// Transaction or block could not be decoded from hex.
pub const RPC_DESERIALIZATION_ERROR: i32 = -22;
/// Transaction rejected by network rules.
pub const RPC_VERIFY_REJECTED: i32 = -26;

/// An error reported to the JSON-RPC client as `{"code", "message"}`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub type RpcResult<T> = Result<T, RpcError>;
