//! Andras core: the checks that sit between an MCP client and an MCP server.
//!
//! Everything here is synchronous and transport-agnostic. The CLI feeds raw
//! JSON-RPC messages into [`Gate`] and acts on the returned [`Verdict`]; the
//! eval harness does the same in-process.

pub mod audit;
pub mod gate;
pub mod pin;
pub mod policy;
pub mod scan;
pub mod secrets;

pub use audit::AuditLog;
pub use gate::{Gate, Verdict};
pub use pin::PinStore;
pub use policy::Policy;
