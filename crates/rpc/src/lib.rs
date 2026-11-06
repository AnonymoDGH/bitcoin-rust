//! `btc-rpc`: JSON-RPC 1.0/2.0 over HTTP (port of `src/httpserver.cpp`,
//! `src/httprpc.cpp` and `src/rpc/request.cpp`), decoupled from the node by
//! [`RpcBackend`].

mod backend;
mod cookie;
mod dispatch;
pub mod error;
mod http;
mod json;
mod methods;
mod params;

pub use backend::{BlockchainInfo, MempoolInfo, RpcBackend, WalletInfo, WalletRpc, WalletTx, WalletUtxo};
pub use cookie::write_cookie;
pub use dispatch::dispatch;
pub use error::{RpcError, RpcResult};
pub use http::{serve, serve_listener};
