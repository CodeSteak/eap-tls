#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "tls")]
mod eap_rustls;

mod layers;
mod message;
pub mod util;

pub mod environment;
pub use environment::*;

#[cfg(feature = "std")]
mod wrapper;
#[cfg(feature = "std")]
pub use wrapper::*;

#[cfg(feature = "tls")]
pub use dummycert::TlsConfig;
