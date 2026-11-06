//! Positional and named parameter handling (`transformNamedArguments` and the
//! `RPCTypeCheck` helpers of Core).

use std::fmt::Display;
use std::str::FromStr;

use serde_json::Value;

use crate::error::{RpcError, RpcResult, RPC_INVALID_PARAMETER, RPC_TYPE_ERROR};

/// Turns the `params` member of a request into the positional list that the
/// method expects. `spec` lists `(name, required)` in positional order.
pub(crate) fn normalize(spec: &[(&str, bool)], given: &Value) -> RpcResult<Vec<Value>> {
    match given {
        Value::Object(named) => {
            if let Some(key) = named
                .keys()
                .find(|key| !spec.iter().any(|(name, _)| name == key))
            {
                return Err(RpcError::new(
                    RPC_INVALID_PARAMETER,
                    format!("Unknown named parameter {key}"),
                ));
            }
            let mut positional = Vec::with_capacity(spec.len());
            for &(name, required) in spec {
                match named.get(name) {
                    Some(value) if !value.is_null() => positional.push(value.clone()),
                    _ if required => return Err(missing(name)),
                    _ => positional.push(Value::Null),
                }
            }
            while positional.last().is_some_and(Value::is_null) {
                positional.pop();
            }
            Ok(positional)
        }
        Value::Array(values) => {
            if values.len() > spec.len() {
                return Err(RpcError::new(
                    RPC_INVALID_PARAMETER,
                    format!("Too many arguments (maximum {})", spec.len()),
                ));
            }
            for (i, &(name, required)) in spec.iter().enumerate() {
                if required && values.get(i).is_none_or(Value::is_null) {
                    return Err(missing(name));
                }
            }
            Ok(values.clone())
        }
        _ => Ok(Vec::new()),
    }
}

/// Positional arguments of one call. Null counts as absent, as in Core.
pub(crate) struct Args(Vec<Value>);

impl Args {
    pub(crate) fn new(values: Vec<Value>) -> Self {
        Self(values)
    }

    fn get(&self, i: usize) -> Option<&Value> {
        self.0.get(i).filter(|value| !value.is_null())
    }

    pub(crate) fn is_set(&self, i: usize) -> bool {
        self.get(i).is_some()
    }

    pub(crate) fn u32(&self, i: usize) -> RpcResult<Option<u32>> {
        let Some(value) = self.get(i) else {
            return Ok(None);
        };
        if let Some(n) = value.as_u64() {
            return u32::try_from(n).map(Some).map_err(|_| out_of_range());
        }
        if value.is_i64() {
            return Err(out_of_range());
        }
        if value.is_number() {
            return Err(type_error("integer", value));
        }
        Err(type_error("number", value))
    }

    pub(crate) fn u32_req(&self, i: usize, name: &str) -> RpcResult<u32> {
        self.u32(i)?.ok_or_else(|| missing(name))
    }

    pub(crate) fn bool(&self, i: usize, default: bool) -> RpcResult<bool> {
        match self.get(i) {
            None => Ok(default),
            Some(value) => value.as_bool().ok_or_else(|| type_error("bool", value)),
        }
    }

    pub(crate) fn str(&self, i: usize) -> RpcResult<Option<&str>> {
        match self.get(i) {
            None => Ok(None),
            Some(value) => value
                .as_str()
                .map(Some)
                .ok_or_else(|| type_error("string", value)),
        }
    }

    pub(crate) fn str_req(&self, i: usize, name: &str) -> RpcResult<&str> {
        self.str(i)?.ok_or_else(|| missing(name))
    }

    /// Parses a required hex-encoded hash (`ParseHashV`).
    pub(crate) fn hash_req<T>(&self, i: usize, name: &str) -> RpcResult<T>
    where
        T: FromStr,
        T::Err: Display,
    {
        let text = self.str_req(i, name)?;
        text.parse::<T>().map_err(|err| {
            RpcError::new(
                RPC_INVALID_PARAMETER,
                format!("{name} must be a hexadecimal hash: {err} (not '{text}')"),
            )
        })
    }
}

fn missing(name: &str) -> RpcError {
    RpcError::new(
        RPC_INVALID_PARAMETER,
        format!("Missing required parameter {name}"),
    )
}

fn out_of_range() -> RpcError {
    RpcError::new(RPC_INVALID_PARAMETER, "Parameter value out of range")
}

fn type_error(expected: &str, value: &Value) -> RpcError {
    RpcError::new(
        RPC_TYPE_ERROR,
        format!(
            "JSON value of type {} is not of expected type {expected}",
            type_name(value)
        ),
    )
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
