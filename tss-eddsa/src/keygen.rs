use curv::{
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::{Ed25519, Point, Scalar},
    BigInt,
};
use multi_party_eddsa::protocols::thresholdsig::{
    KeyGenBroadcastMessage1, Keys, Parameters, SharedKeys,
};
use serde::{Deserialize, Serialize};

use crate::{error::TssError, TssResult};

// party one structures
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenContext1 {
    pub params: Parameters,
    pub keypair: Keys,
    pub first_msg_blind: BigInt,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenMsg1 {
    pub sender: u16,
    pub msg: KeyGenBroadcastMessage1,
}

//party two structures
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenContext2 {
    pub params: Parameters,
    pub keypair: Keys,
    pub comm_vec: Vec<KeyGenBroadcastMessage1>,
}

// party one structures
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenMsg2 {
    pub sender: u16,
    pub pubkey: Point<Ed25519>,
    pub first_msg_blind: BigInt,
}

//party two structures
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenContext3 {
    pub params: Parameters,
    pub keypair: Keys,
    pub pubkeys_vec: Vec<Point<Ed25519>>,
    pub agg_pubkey: Point<Ed25519>,
}

// party one structures
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenMsg3 {
    pub sender: u16,
    pub receiver: u16,
    pub secret_share: Scalar<Ed25519>,
    pub vss_scheme: VerifiableSS<Ed25519>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecretShare {
    pub keypair: Keys,
    pub shared_keys: SharedKeys,
}

//party two structures
#[derive(Clone, Serialize, Deserialize)]
pub struct SignKey {
    pub params: Parameters,
    pub agg_pubkey: Point<Ed25519>,
    pub vss_schemes: Vec<VerifiableSS<Ed25519>>,
    pub secret_share: SecretShare,
}

pub fn keygen_phase1(t: u16, n: u16, party_index: u16) -> TssResult<(KeyGenContext1, KeyGenMsg1)> {
    let key = Keys::phase1_create(party_index);

    let (first_msg, first_msg_blind) = key.phase1_broadcast();

    let context1 = KeyGenContext1 {
        params: Parameters {
            threshold: t,
            share_count: n,
        },
        keypair: key,
        first_msg_blind,
    };

    let msg1 = KeyGenMsg1 {
        sender: party_index,
        msg: first_msg,
    };

    Ok((context1, msg1))
}

pub fn keygen_phase2(
    context1: KeyGenContext1,
    mut msgs1: Vec<KeyGenMsg1>,
) -> TssResult<(KeyGenContext2, KeyGenMsg2)> {
    msgs1.sort_by(|a, b| a.sender.cmp(&b.sender));

    let comm_vec = msgs1.into_iter().map(|msg| msg.msg).collect();

    let msg2 = KeyGenMsg2 {
        sender: context1.keypair.party_index,
        pubkey: context1.keypair.keypair.public_key.clone(),
        first_msg_blind: context1.first_msg_blind,
    };

    let context2 = KeyGenContext2 {
        params: context1.params,
        keypair: context1.keypair,
        comm_vec,
    };

    Ok((context2, msg2))
}

pub fn keygen_phase3(
    context2: KeyGenContext2,
    mut msgs2: Vec<KeyGenMsg2>,
) -> TssResult<(KeyGenContext3, Vec<KeyGenMsg3>)> {
    msgs2.sort_by(|a, b| a.sender.cmp(&b.sender));

    let (blind_vec, pubkeys_vec): (Vec<_>, Vec<_>) = msgs2
        .into_iter()
        .map(|msg2| (msg2.first_msg_blind, msg2.pubkey))
        .unzip();

    if blind_vec.len() != usize::from(context2.params.share_count)
        || pubkeys_vec.len() != usize::from(context2.params.share_count)
        || context2.comm_vec.len() != usize::from(context2.params.share_count)
    {
        return Err(TssError::InputsLengthUnmatch);
    }
    let agg_pubkey = {
        let first_key = pubkeys_vec[0].clone();
        pubkeys_vec[1..].iter().fold(first_key, |acc, p| acc + p)
    };

    let parties: Vec<_> = (1..=context2.params.share_count).collect();

    let (vss_scheme, secret_shares) = context2.keypair.phase1_verify_com_phase2_distribute(
        &context2.params,
        &blind_vec,
        &pubkeys_vec,
        &context2.comm_vec,
        &parties,
    )?;
    let mut msg3 = vec![];
    for i in 0..secret_shares.len() {
        msg3.push(KeyGenMsg3 {
            sender: context2.keypair.party_index,
            receiver: i as u16 + 1,
            secret_share: secret_shares[i].clone(),
            vss_scheme: vss_scheme.clone(),
        });
    }

    let context3 = KeyGenContext3 {
        params: context2.params,
        keypair: context2.keypair,
        pubkeys_vec,
        agg_pubkey,
    };
    Ok((context3, msg3))
}

pub fn keygen_phase4(context3: KeyGenContext3, mut msgs3: Vec<KeyGenMsg3>) -> TssResult<SignKey> {
    msgs3.sort_by(|a, b| a.sender.cmp(&b.sender));

    let secret_shares_vec = msgs3
        .iter()
        .map(|msg| msg.secret_share.clone())
        .collect::<Vec<_>>();
    let vss_scheme_vec = msgs3
        .iter()
        .map(|msg| msg.vss_scheme.clone())
        .collect::<Vec<_>>();

    if secret_shares_vec.len() != usize::from(context3.params.share_count)
        || vss_scheme_vec.len() != usize::from(context3.params.share_count)
        || context3.pubkeys_vec.len() != usize::from(context3.params.share_count)
    {
        return Err(TssError::InputsLengthUnmatch);
    }

    let shared_keys = context3.keypair.phase2_verify_vss_construct_keypair(
        &context3.params,
        &context3.pubkeys_vec,
        &secret_shares_vec,
        &vss_scheme_vec,
        context3.keypair.party_index,
    )?;

    Ok(SignKey {
        params: context3.params,
        agg_pubkey: context3.agg_pubkey,
        vss_schemes: vss_scheme_vec,
        secret_share: SecretShare {
            keypair: context3.keypair,
            shared_keys,
        },
    })
}
