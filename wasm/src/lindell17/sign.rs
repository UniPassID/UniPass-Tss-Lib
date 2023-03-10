use curv::arithmetic::traits::*;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use curv::BigInt;
use gloo_utils::format::JsValueSerdeExt;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::SignatureRecid;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsError, JsValue};

use super::keygen::{Li17SignP1Context, Li17SignP2Context};

#[derive(Serialize, Deserialize)]
pub struct Li17SignP2Context1 {
    pub public: Point<Secp256k1>,
    pub p2_private: party_two::Party2Private,
    pub p2_paillier_public: party_two::PaillierPublic,
    hash: BigInt,
    p2_eph_comm_witness: party_two::EphCommWitness,
    p2_eph_ec_key_pair: party_two::EphEcKeyPair,
}

pub type Li17SignP2Msg1 = party_two::EphKeyGenFirstMsg;

pub type Li17SignP2Msg2 = (party_two::PartialSig, party_two::EphKeyGenSecondMsg);

#[derive(Clone, Serialize, Deserialize)]
pub struct Li17SignP1Context1 {
    pub public: Point<Secp256k1>,
    pub p1_private: party_one::Party1Private,
    hash: BigInt,
    p1_eph_ec_key_pair: party_one::EphEcKeyPair,
    p1_msg1_from_p2: Li17SignP2Msg1,
}

pub type Li17SignP1Msg1 = party_one::EphKeyGenFirstMsg;

#[wasm_bindgen]
pub fn li17_p2_sign1(context: JsValue, message_hash: JsValue) -> Result<JsValue, JsError> {
    let context: Li17SignP2Context = context.into_serde()?;
    let message_hash: Vec<u8> = message_hash.into_serde()?;
    let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        party_two::EphKeyGenFirstMsg::create_commitments();

    let context1 = Li17SignP2Context1 {
        public: context.public,
        p2_private: context.p2_private,
        p2_paillier_public: context.p2_paillier_public,
        hash: BigInt::from_bytes(&message_hash),
        p2_eph_comm_witness: eph_comm_witness,
        p2_eph_ec_key_pair: eph_ec_key_pair_party2,
    };
    Ok(JsValue::from_serde(&(
        context1,
        eph_party_two_first_message,
    ))?)
}

#[wasm_bindgen]
pub fn li17_p2_sign2(context: JsValue, msg: JsValue) -> Result<JsValue, JsError> {
    let context: Li17SignP2Context1 = context.into_serde()?;
    let msg: Li17SignP1Msg1 = msg.into_serde()?;
    let eph_party_two_second_message =
        party_two::EphKeyGenSecondMsg::verify_and_decommit(context.p2_eph_comm_witness, &msg)?;

    let partial_sig = party_two::PartialSig::compute(
        &context.p2_paillier_public.ek,
        &context.p2_paillier_public.encrypted_secret_share,
        &context.p2_private,
        &context.p2_eph_ec_key_pair,
        &msg.public_share,
        &context.hash,
    );
    Ok(JsValue::from_serde(&(
        partial_sig,
        eph_party_two_second_message,
    ))?)
}

#[wasm_bindgen]
pub fn li17_p1_sign1(
    context: JsValue,
    msg: JsValue,
    message_hash: JsValue,
) -> Result<JsValue, JsError> {
    let context: Li17SignP1Context = context.into_serde()?;
    let msg: Li17SignP2Msg1 = msg.into_serde()?;
    let message_hash: Vec<u8> = message_hash.into_serde()?;

    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
        party_one::EphKeyGenFirstMsg::create();
    let context2 = Li17SignP1Context1 {
        public: context.public,
        p1_private: context.p1_private,
        hash: BigInt::from_bytes(&message_hash),
        p1_eph_ec_key_pair: eph_ec_key_pair_party1,
        p1_msg1_from_p2: msg,
    };
    Ok(JsValue::from_serde(&(
        context2,
        eph_party_one_first_message,
    ))?)
}

#[wasm_bindgen]
pub fn li17_p1_sign2(context: JsValue, msg: JsValue) -> Result<JsValue, JsError> {
    let context: Li17SignP1Context1 = context.into_serde()?;
    let msg: Li17SignP2Msg2 = msg.into_serde()?;
    let (partial_sig, eph_party_two_second_message) = msg;

    party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &context.p1_msg1_from_p2,
        &eph_party_two_second_message,
    )?;

    let sig = party_one::Signature::compute_with_recid(
        &context.p1_private,
        &partial_sig.c3,
        &context.p1_eph_ec_key_pair,
        &eph_party_two_second_message.comm_witness.public_share,
    );

    verify(&sig, &context.public, &context.hash)?;

    Ok(JsValue::from_serde(&sig)?)
}

pub fn verify(sig: &SignatureRecid, y: &Point<Secp256k1>, message: &BigInt) -> Result<(), JsError> {
    let r = Scalar::<Secp256k1>::from(&sig.r);
    let s = Scalar::<Secp256k1>::from(&sig.s);
    let b = s.invert().unwrap();
    let a = Scalar::<Secp256k1>::from(message);
    let u1 = a * &b;
    let u2 = &r * &b;

    let g = Point::generator();
    let gu1 = g * u1;
    let yu2 = y * &u2;
    // can be faster using shamir trick
    if r == Scalar::<Secp256k1>::from(
        &(gu1 + yu2)
            .x_coord()
            .unwrap()
            .mod_floor(Scalar::<Secp256k1>::group_order()),
    ) {
        Ok(())
    } else {
        Err(JsError::new("verify failed"))
    }
}
