use curv::{
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::{Ed25519, Point, Scalar},
    BigInt,
};
use multi_party_eddsa::protocols::{
    thresholdsig::{self, EphemeralKey, KeyGenBroadcastMessage1, LocalSig, Parameters},
    Signature,
};
use serde::{Deserialize, Serialize};

use crate::{error::TssError, keygen::SignKey, TssResult};

// party one structures
#[derive(Clone, Serialize, Deserialize)]
pub struct SignContext1 {
    pub params: Parameters,
    pub parties: Vec<u16>,
    pub message: Vec<u8>,
    pub nonce_key: EphemeralKey,
    pub first_msg_blind: BigInt,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignMsg1 {
    pub sender: u16,
    pub msg: KeyGenBroadcastMessage1,
}

//party two structures
#[derive(Clone, Serialize, Deserialize)]
pub struct SignContext2 {
    pub params: Parameters,
    pub parties: Vec<u16>,
    pub message: Vec<u8>,
    pub nonce_key: EphemeralKey,
    pub comm_vec: Vec<KeyGenBroadcastMessage1>,
}

// party one structures
#[derive(Clone, Serialize, Deserialize)]
pub struct SignMsg2 {
    pub sender: u16,
    pub nonce_pk: Point<Ed25519>,
    pub first_msg_blind: BigInt,
}

//party two structures
#[derive(Clone, Serialize, Deserialize)]
pub struct SignContext3 {
    pub params: Parameters,
    pub parties: Vec<u16>,
    pub message: Vec<u8>,
    pub nonce_key: EphemeralKey,
    pub nonce_keys_vec: Vec<Point<Ed25519>>,
    pub agg_nonce: Point<Ed25519>,
}

// party one structures
#[derive(Clone, Serialize, Deserialize)]
pub struct SignMsg3 {
    pub sender: u16,
    pub receiver: u16,
    pub secret_share: Scalar<Ed25519>,
    pub vss_scheme: VerifiableSS<Ed25519>,
}

//party two structures
#[derive(Clone, Serialize, Deserialize)]
pub struct SignContext4 {
    pub params: Parameters,
    pub parties: Vec<u16>,
    pub message: Vec<u8>,
    pub agg_nonce: Point<Ed25519>,
    pub nonce_vss_schemes: Vec<VerifiableSS<Ed25519>>,
}

// party one structures
#[derive(Clone, Serialize, Deserialize)]
pub struct SignMsg4 {
    pub sender: u16,
    pub partial_sig: LocalSig,
}

pub fn sign_phase1(
    sign_key: &SignKey,
    mut parties: Vec<u16>,
    message: &[u8],
) -> TssResult<(SignContext1, SignMsg1)> {
    parties.sort_by(|a, b| a.cmp(&b));

    let nonce_key = EphemeralKey::ephermeral_key_create_from_deterministic_secret(
        &sign_key.secret_share.keypair,
        message,
        sign_key.secret_share.keypair.party_index,
    );

    let (first_msg, first_msg_blind) = nonce_key.phase1_broadcast();
    let params = Parameters {
        threshold: sign_key.params.threshold,
        share_count: parties.len() as u16,
    };

    let sign_context1 = SignContext1 {
        params,
        parties,
        message: message.to_vec(),
        nonce_key,
        first_msg_blind,
    };

    let sign_msg1 = SignMsg1 {
        sender: sign_key.secret_share.keypair.party_index,
        msg: first_msg,
    };

    Ok((sign_context1, sign_msg1))
}

pub fn sign_phase2(
    sign_key: &SignKey,
    context1: SignContext1,
    mut msgs1: Vec<SignMsg1>,
) -> TssResult<(SignContext2, SignMsg2)> {
    msgs1.sort_by(|a, b| a.sender.cmp(&b.sender));

    let comm_vec = msgs1.into_iter().map(|msg| msg.msg).collect();

    let msg2 = SignMsg2 {
        sender: sign_key.secret_share.keypair.party_index,
        nonce_pk: context1.nonce_key.R_i.clone(),
        first_msg_blind: context1.first_msg_blind,
    };

    let context2 = SignContext2 {
        params: context1.params,
        parties: context1.parties,
        message: context1.message,
        nonce_key: context1.nonce_key,
        comm_vec,
    };

    Ok((context2, msg2))
}

pub fn sign_phase3(
    sign_key: &SignKey,
    context2: SignContext2,
    mut msgs2: Vec<SignMsg2>,
) -> TssResult<(SignContext3, Vec<SignMsg3>)> {
    msgs2.sort_by(|a, b| a.sender.cmp(&b.sender));

    let (blind_vec, nonce_keys_vec): (Vec<_>, Vec<_>) = msgs2
        .into_iter()
        .map(|msg2| (msg2.first_msg_blind, msg2.nonce_pk))
        .unzip();
    let agg_nonce = {
        let first_key = nonce_keys_vec[0].clone();
        nonce_keys_vec[1..].iter().fold(first_key, |acc, p| acc + p)
    };

    if !(blind_vec.len() > usize::from(context2.params.threshold)
        && blind_vec.len() <= usize::from(context2.params.share_count))
        || !(context2.comm_vec.len() > usize::from(context2.params.threshold)
            && context2.comm_vec.len() <= usize::from(context2.params.share_count))
        || !(nonce_keys_vec.len() > usize::from(context2.params.threshold)
            && nonce_keys_vec.len() <= usize::from(context2.params.share_count))
    {
        return Err(TssError::SpecificError("inputs length unmatch".into()));
    }

    let (nonce_vss_scheme, nonce_secret_share) =
        context2.nonce_key.phase1_verify_com_phase2_distribute(
            &context2.params,
            &blind_vec,
            &nonce_keys_vec,
            &context2.comm_vec,
            &context2.parties,
        )?;
    let mut msg3 = vec![];
    for (index, &receiver) in context2.parties.iter().enumerate() {
        msg3.push(SignMsg3 {
            sender: sign_key.secret_share.keypair.party_index,
            receiver,
            secret_share: nonce_secret_share[index].clone(),
            vss_scheme: nonce_vss_scheme.clone(),
        });
    }

    let context3 = SignContext3 {
        params: context2.params,
        parties: context2.parties,
        message: context2.message,
        nonce_key: context2.nonce_key,
        nonce_keys_vec,
        agg_nonce,
    };
    Ok((context3, msg3))
}

pub fn sign_phase4(
    sign_key: &SignKey,
    context3: SignContext3,
    mut msgs3: Vec<SignMsg3>,
) -> TssResult<(SignContext4, SignMsg4)> {
    msgs3.sort_by(|a, b| a.sender.cmp(&b.sender));

    let secret_shares_vec = msgs3
        .iter()
        .map(|msg| msg.secret_share.clone())
        .collect::<Vec<_>>();
    let vss_scheme_vec = msgs3
        .iter()
        .map(|msg| msg.vss_scheme.clone())
        .collect::<Vec<_>>();

    if !(vss_scheme_vec.len() > usize::from(context3.params.threshold)
        && vss_scheme_vec.len() <= usize::from(context3.params.share_count))
        || !(secret_shares_vec.len() > usize::from(context3.params.threshold)
            && secret_shares_vec.len() <= usize::from(context3.params.share_count))
        || !(context3.nonce_keys_vec.len() > usize::from(context3.params.threshold)
            && context3.nonce_keys_vec.len() <= usize::from(context3.params.share_count))
    {
        return Err(TssError::InputsLengthUnmatch);
    }

    let shared_keys = context3.nonce_key.phase2_verify_vss_construct_keypair(
        &context3.params,
        &context3.nonce_keys_vec,
        &secret_shares_vec,
        &vss_scheme_vec,
        sign_key.secret_share.keypair.party_index,
    )?;

    let partial_sig = LocalSig::compute(
        &context3.message,
        &shared_keys,
        &sign_key.secret_share.shared_keys,
    );

    let context4 = SignContext4 {
        params: context3.params,
        parties: context3.parties,
        message: context3.message,
        agg_nonce: context3.agg_nonce,
        nonce_vss_schemes: vss_scheme_vec,
    };

    let msg4 = SignMsg4 {
        sender: sign_key.secret_share.keypair.party_index,
        partial_sig,
    };

    Ok((context4, msg4))
}

pub fn sign_phase5(
    sign_key: &SignKey,
    context4: SignContext4,
    mut msgs4: Vec<SignMsg4>,
) -> TssResult<Signature> {
    msgs4.sort_by(|a, b| a.sender.cmp(&b.sender));

    let partial_sigs: Vec<_> = msgs4.into_iter().map(|msg| msg.partial_sig).collect();
    let parties_indexs: Vec<_> = context4.parties.iter().map(|a| a - 1).collect();
    let vss_sum_sigs = LocalSig::verify_local_sigs(
        &partial_sigs,
        &parties_indexs,
        &sign_key.vss_schemes,
        &context4.nonce_vss_schemes,
    )?;

    let sig = thresholdsig::generate(
        &vss_sum_sigs,
        &partial_sigs,
        &parties_indexs,
        context4.agg_nonce,
    );

    sig.verify(&context4.message, &sign_key.agg_pubkey)?;

    return Ok(sig);
}
