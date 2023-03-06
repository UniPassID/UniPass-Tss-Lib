use gloo_utils::format::JsValueSerdeExt;
use tss_eddsa::{keygen::SignKey, sign::*};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn eddsa_sign_phase1(
    sign_key: JsValue,
    parties: JsValue,
    message: JsValue,
) -> Result<JsValue, JsError> {
    let sign_key: SignKey = sign_key.into_serde()?;
    let parties: Vec<u16> = parties.into_serde()?;
    let message: Vec<u8> = message.into_serde()?;

    let (context1, msgs1) = tss_eddsa::sign::sign_phase1(&sign_key, parties, &message)?;
    Ok(JsValue::from_serde(&(context1, msgs1))?)
}

#[wasm_bindgen]
pub fn eddsa_sign_phase2(
    sign_key: JsValue,
    context1: JsValue,
    msgs1: JsValue,
) -> Result<JsValue, JsError> {
    let sign_key: SignKey = sign_key.into_serde()?;
    let context1: SignContext1 = context1.into_serde()?;
    let msgs1: Vec<SignMsg1> = msgs1.into_serde()?;

    let (context2, msgs2) = tss_eddsa::sign::sign_phase2(&sign_key, context1, msgs1)?;
    Ok(JsValue::from_serde(&(context2, msgs2))?)
}

#[wasm_bindgen]
pub fn eddsa_sign_phase3(
    sign_key: JsValue,
    context2: JsValue,
    msgs2: JsValue,
) -> Result<JsValue, JsError> {
    let sign_key: SignKey = sign_key.into_serde()?;
    let context2: SignContext2 = context2.into_serde()?;
    let msgs2: Vec<SignMsg2> = msgs2.into_serde()?;

    let (context3, msgs3) = tss_eddsa::sign::sign_phase3(&sign_key, context2, msgs2)?;
    Ok(JsValue::from_serde(&(context3, msgs3))?)
}

#[wasm_bindgen]
pub fn eddsa_sign_phase4(
    sign_key: JsValue,
    context3: JsValue,
    msgs3: JsValue,
) -> Result<JsValue, JsError> {
    let sign_key: SignKey = sign_key.into_serde()?;
    let context3: SignContext3 = context3.into_serde()?;
    let msgs3: Vec<SignMsg3> = msgs3.into_serde()?;

    let (context4, msgs4) = tss_eddsa::sign::sign_phase4(&sign_key, context3, msgs3)?;
    Ok(JsValue::from_serde(&(context4, msgs4))?)
}

#[wasm_bindgen]
pub fn eddsa_sign_phase5(
    sign_key: JsValue,
    context4: JsValue,
    msgs4: JsValue,
) -> Result<JsValue, JsError> {
    let sign_key: SignKey = sign_key.into_serde()?;
    let context4: SignContext4 = context4.into_serde()?;
    let msgs4: Vec<SignMsg4> = msgs4.into_serde()?;

    let signature = tss_eddsa::sign::sign_phase5(&sign_key, context4, msgs4)?;
    Ok(JsValue::from_serde(&signature)?)
}
