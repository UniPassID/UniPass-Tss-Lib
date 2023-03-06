use curv::{
    elliptic::curves::{Point, Scalar, Secp256k1},
    BigInt,
};
use multi_party_ecdsa::{
    protocols::two_party_ecdsa::lindell_2017::{party_one, party_two},
    utilities::zk_pdl_with_slack::{PDLwSlackProof, PDLwSlackStatement},
};
use paillier::EncryptionKey;
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::{CompositeDLogProof, NiCorrectKeyProof};

use crate::error::LindellError;

// party one structures
#[derive(Clone, Serialize, Deserialize)]
pub struct Li17KeyGenP1Context1 {
    p1_ec_key_pair: party_one::EcKeyPair,
    p1_comm_witness: party_one::CommWitness,
}

pub type Li17KeyGenP1Msg1 = party_one::KeyGenFirstMsg;

#[derive(Clone, Serialize, Deserialize)]
pub struct Li17SignP1Context {
    pub public: Point<Secp256k1>,
    pub public_p1: Point<Secp256k1>,
    pub public_p2: Point<Secp256k1>,
    pub p1_private: party_one::Party1Private,
}

pub type Li17KeyGenP1Msg2 = (
    party_one::KeyGenSecondMsg,
    NiCorrectKeyProof,
    PDLwSlackStatement,
    PDLwSlackProof,
    CompositeDLogProof,
    EncryptionKey,
    BigInt,
);

//party two structures
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Li17KeyGenP2Context1 {
    p2_msg1_from_p1: party_one::KeyGenFirstMsg,
    p2_ec_key_pair: party_two::EcKeyPair,
}

pub type Li17KeyGenP2Msg1 = party_two::KeyGenFirstMsg;

#[derive(Serialize, Deserialize)]
pub struct Li17SignP2Context {
    pub public: Point<Secp256k1>,
    pub public_p1: Point<Secp256k1>,
    pub public_p2: Point<Secp256k1>,
    pub p2_private: party_two::Party2Private,
    pub p2_paillier_public: party_two::PaillierPublic,
}

pub type Li17KeyGenP2Msg2 = Point<Secp256k1>;

// party one functions

pub fn li17_p1_key_gen1() -> Result<(Li17KeyGenP1Context1, Li17KeyGenP1Msg1), LindellError> {
    let (party1_first_message, p1_comm_witness, p1_ec_key_pair) =
        party_one::KeyGenFirstMsg::create_commitments();
    let context1 = Li17KeyGenP1Context1 {
        p1_ec_key_pair,
        p1_comm_witness,
    };
    Ok((context1, party1_first_message))
}

pub fn li17_p1_key_gen1_with_fixed_secret_share(
    secret_share: Scalar<Secp256k1>,
) -> Result<(Li17KeyGenP1Context1, Li17KeyGenP1Msg1), LindellError> {
    let (party1_first_message, p1_comm_witness, p1_ec_key_pair) =
        party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(secret_share);
    let context1 = Li17KeyGenP1Context1 {
        p1_ec_key_pair,
        p1_comm_witness,
    };
    Ok((context1, party1_first_message))
}

pub fn li17_p1_key_gen2(
    context: Li17KeyGenP1Context1,
    msg: Li17KeyGenP2Msg1,
) -> Result<(Li17SignP1Context, Li17KeyGenP1Msg2), LindellError> {
    let p1_second_message =
        party_one::KeyGenSecondMsg::verify_and_decommit(context.p1_comm_witness, &msg.d_log_proof)?;

    let paillier_key_pair =
        party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&context.p1_ec_key_pair);
    let party_one_private =
        party_one::Party1Private::set_private_key(&context.p1_ec_key_pair, &paillier_key_pair);

    let correct_key_proof =
        party_one::PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);

    let (pdl_statement, pdl_proof, composite_dlog_proof) =
        party_one::PaillierKeyPair::pdl_proof(&party_one_private, &paillier_key_pair);
    let ek = paillier_key_pair.ek.clone();
    let encrypted_share = paillier_key_pair.encrypted_share.clone();

    let party_one_private =
        party_one::Party1Private::set_private_key(&context.p1_ec_key_pair, &paillier_key_pair);
    let public_key = party_one::compute_pubkey(&party_one_private, &msg.public_share);
    let sign_context = Li17SignP1Context {
        public: public_key.clone(),
        public_p1: context.p1_ec_key_pair.public_share,
        public_p2: msg.public_share,
        p1_private: party_one_private,
    };
    let p1_msg2_for_p2 = (
        p1_second_message,
        correct_key_proof,
        pdl_statement,
        pdl_proof,
        composite_dlog_proof,
        ek,
        encrypted_share,
    );
    Ok((sign_context, p1_msg2_for_p2))
}

// party two functions
pub fn li17_p2_key_gen1(
    msg: Li17KeyGenP1Msg1,
) -> Result<(Li17KeyGenP2Context1, Li17KeyGenP2Msg1), LindellError> {
    let (p2_first_message, p2_ec_key_pair) = party_two::KeyGenFirstMsg::create();
    let context2 = Li17KeyGenP2Context1 {
        p2_msg1_from_p1: msg,
        p2_ec_key_pair,
    };
    Ok((context2, p2_first_message))
}

pub fn li17_p2_key_gen1_with_fixed_secret_share(
    secret_share: Scalar<Secp256k1>,
    msg: Li17KeyGenP1Msg1,
) -> Result<(Li17KeyGenP2Context1, Li17KeyGenP2Msg1), LindellError> {
    let (p2_first_message, p2_ec_key_pair) =
        party_two::KeyGenFirstMsg::create_with_fixed_secret_share(secret_share);
    let context2 = Li17KeyGenP2Context1 {
        p2_msg1_from_p1: msg,
        p2_ec_key_pair,
    };
    Ok((context2, p2_first_message))
}

pub fn li17_p2_key_gen2(
    context: Li17KeyGenP2Context1,
    msg: Li17KeyGenP1Msg2,
) -> Result<(Li17SignP2Context, Point<Secp256k1>), LindellError> {
    let (
        party_one_second_message,
        correct_key_proof,
        pdl_statement,
        pdl_proof,
        composite_dlog_proof,
        paillier_ek,
        paillier_encrypted_share,
    ) = msg;

    party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &context.p2_msg1_from_p1,
        &party_one_second_message,
    )?;

    let party_two_paillier = party_two::PaillierPublic {
        ek: paillier_ek.clone(),
        encrypted_secret_share: paillier_encrypted_share.clone(),
    };

    party_two::PaillierPublic::verify_ni_proof_correct_key(
        correct_key_proof,
        &party_two_paillier.ek,
    )
    .expect("bad paillier key");

    party_two::PaillierPublic::pdl_verify(
        &composite_dlog_proof,
        &pdl_statement,
        &pdl_proof,
        &party_two_paillier,
        &party_one_second_message.comm_witness.public_share,
    )
    .expect("PDL error");

    let party_two_private = party_two::Party2Private::set_private_key(&context.p2_ec_key_pair);
    let public_key = party_two::compute_pubkey(
        &context.p2_ec_key_pair,
        &party_one_second_message.comm_witness.public_share,
    );

    let sign_context = Li17SignP2Context {
        public: public_key.clone(),
        public_p1: party_one_second_message.comm_witness.public_share,
        public_p2: context.p2_ec_key_pair.public_share,
        p2_private: party_two_private,
        p2_paillier_public: party_two_paillier,
    };

    Ok((sign_context, public_key))
}
