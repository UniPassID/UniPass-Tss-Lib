use gloo_utils::format::JsValueSerdeExt;

use wasm_bindgen::prelude::*;

#[cfg(all(test, target_arch = "wasm32"))]
extern crate wasm_bindgen_test;

#[doc(hidden)]
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    if let Ok(_) = wasm_log::try_init(wasm_log::Config::new(log::Level::Debug)) {
        log::info!("WASM logger initialized");
    }
    log::info!("WASM: module started {:?}", std::thread::current().id());
}

/// Compute the Keccak256 hash of a value.
#[wasm_bindgen]
pub fn keccak256(message: JsValue) -> Result<JsValue, JsError> {
    use sha3::{Digest, Keccak256};
    let message: Vec<u8> = message.into_serde()?;
    let digest = Keccak256::digest(&message).to_vec();
    Ok(JsValue::from_serde(&digest)?)
}
