#[allow(
    non_camel_case_types,
    non_upper_case_globals,
    improper_ctypes,
    non_snake_case,
    clippy::all
)] // improper_ctypes for u128 values
pub(crate) mod bindings_peer;

#[allow(
    non_camel_case_types,
    non_upper_case_globals,
    improper_ctypes,
    non_snake_case,
    clippy::all
)] // improper_ctypes for u128 values
pub(crate) mod bindings_server;

pub mod peer;
pub mod server;
pub mod util;
