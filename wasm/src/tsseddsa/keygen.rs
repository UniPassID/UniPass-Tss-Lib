use gloo_utils::format::JsValueSerdeExt;
use tss_eddsa::keygen::*;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn eddsa_keygen_phase1(t: u16, n: u16, party_index: u16) -> Result<JsValue, JsError> {
    let (context1, msg1) = tss_eddsa::keygen::keygen_phase1(t, n, party_index)?;
    Ok(JsValue::from_serde(&(context1, msg1))?)
}

#[wasm_bindgen]
pub fn eddsa_keygen_phase2(context1: JsValue, msgs1: JsValue) -> Result<JsValue, JsError> {
    let context1: KeyGenContext1 = context1.into_serde()?;
    let msgs1: Vec<KeyGenMsg1> = msgs1.into_serde()?;

    let (context2, msg2) = tss_eddsa::keygen::keygen_phase2(context1, msgs1)?;
    Ok(JsValue::from_serde(&(context2, msg2))?)
}

#[wasm_bindgen]
pub fn eddsa_keygen_phase3(context2: JsValue, msgs2: JsValue) -> Result<JsValue, JsError> {
    let context2: KeyGenContext2 = context2.into_serde()?;
    let msgs2: Vec<KeyGenMsg2> = msgs2.into_serde()?;

    let (context3, msg3) = tss_eddsa::keygen::keygen_phase3(context2, msgs2)?;
    Ok(JsValue::from_serde(&(context3, msg3))?)
}

#[wasm_bindgen]
pub fn eddsa_keygen_phase4(context3: JsValue, msgs3: JsValue) -> Result<JsValue, JsError> {
    let context3: KeyGenContext3 = context3.into_serde()?;
    let msgs3: Vec<KeyGenMsg3> = msgs3.into_serde()?;
    let sign_key = tss_eddsa::keygen::keygen_phase4(context3, msgs3)?;
    Ok(JsValue::from_serde(&sign_key)?)
}
