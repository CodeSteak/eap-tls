#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "tls")]
pub mod eap_rustls;

pub mod layers;
mod message;
pub mod util;

pub use common;

pub mod environment;
pub use environment::*;

#[cfg(feature = "std")]
mod wrapper;
#[cfg(feature = "std")]
pub use wrapper::*;

#[cfg(feature = "tls")]
pub use dummycert::TlsConfig;

#[cfg(test)]
mod integration_tests;
