#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(warnings)]

#[cfg(all(feature = "main", feature = "wasm32"))]
compile_error!("Feature \"main\" can't be combined with \"wasm32\".");

#[cfg(feature = "wasm32")]
pub use gloo_console::{debug, error, info, warn};
#[cfg(not(feature = "wasm32"))]
pub use log::{debug, error, info, warn};

#[cfg(feature = "main")]
const ENVKEY_RUST_LOG: &str = "RUST_LOG";

#[cfg(feature = "main")]
pub fn init() {
    if std::env::var(ENVKEY_RUST_LOG).is_err() {
        #[cfg(debug_assertions)]
        std::env::set_var(ENVKEY_RUST_LOG, "debug");
        #[cfg(not(debug_assertions))]
        std::env::set_var(ENVKEY_RUST_LOG, "info");
    }

    env_logger::builder()
        .default_format()
        .format_timestamp_micros()
        .format_indent(Some(2))
        .parse_env(ENVKEY_RUST_LOG)
        .init();
}
