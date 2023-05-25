use curv::{
    elliptic::curves::{Point, Scalar, Secp256k1},
    BigInt,
};
use error::LindellError;
use keygen::{Li17SignP1Context, Li17SignP2Context};
use multi_party_ecdsa::{
    protocols::two_party_ecdsa::lindell_2017::party_one::generate_h1_h2_n_tilde,
    utilities::zk_pdl_with_slack::{PDLwSlackProof, PDLwSlackStatement, PDLwSlackWitness},
};
use paillier::{DecryptionKey, EncryptionKey};
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

#[derive(Serialize, Deserialize)]
pub struct Party2Private {
    pub x2: Scalar<Secp256k1>,
}

#[derive(Serialize, Deserialize)]
pub struct Party1Private {
    x1: Scalar<Secp256k1>,
    paillier_priv: DecryptionKey,
    c_key_randomness: BigInt,
}

pub mod error;
pub mod keygen;
pub mod sign;
pub mod tests;

const ETHPREFIX: &[u8; 26] = b"\x19Ethereum Signed Message:\n";

pub fn keccak256(message: &[u8]) -> Vec<u8> {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(message).to_vec()
}

pub fn hash_message(message: Vec<u8>) -> Vec<u8> {
    let mut msg = Vec::from(ETHPREFIX.as_slice());
    msg.extend_from_slice(message.len().to_string().as_bytes());
    msg.extend_from_slice(&message);
    keccak256(&msg)
}

pub fn li17_p1_exract_secret(
    sign_context: &Li17SignP1Context,
) -> Result<Scalar<Secp256k1>, LindellError> {
    let p1_private: Party1Private = unsafe { std::mem::transmute(sign_context.p1_private.clone()) };
    return Ok(p1_private.x1);
}

pub fn li17_p2_exract_secret(
    sign_context: &Li17SignP2Context,
) -> Result<Scalar<Secp256k1>, LindellError> {
    let p2_private: Party2Private =
        serde_json::from_value(serde_json::to_value(&sign_context.p2_private)?)?;
    return Ok(p2_private.x2);
}

pub fn pdl_proof(
    x: Scalar<Secp256k1>,
    c_key_randomness: BigInt,
    ek: EncryptionKey,
    encrypted_secret_share: BigInt,
) -> (PDLwSlackStatement, PDLwSlackProof, CompositeDLogProof) {
    let (n_tilde, h1, h2, xhi) = generate_h1_h2_n_tilde();
    let dlog_statement = DLogStatement {
        N: n_tilde,
        g: h1,
        ni: h2,
    };
    let composite_dlog_proof = CompositeDLogProof::prove(&dlog_statement, &xhi);

    // Generate PDL with slack statement, witness and proof
    let pdl_w_slack_statement = PDLwSlackStatement {
        ciphertext: encrypted_secret_share,
        ek,
        Q: Point::generator() * &x,
        G: Point::generator().to_point(),
        h1: dlog_statement.g.clone(),
        h2: dlog_statement.ni.clone(),
        N_tilde: dlog_statement.N,
    };

    let pdl_w_slack_witness = PDLwSlackWitness {
        x: x,
        r: c_key_randomness,
    };

    let pdl_w_slack_proof = PDLwSlackProof::prove(&pdl_w_slack_witness, &pdl_w_slack_statement);
    (
        pdl_w_slack_statement,
        pdl_w_slack_proof,
        composite_dlog_proof,
    )
}

pub fn pdl_verify(
    composite_dlog_proof: &CompositeDLogProof,
    pdl_w_slack_statement: &PDLwSlackStatement,
    pdl_w_slack_proof: &PDLwSlackProof,
    ek: EncryptionKey,
    encrypted_secret_share: BigInt,
    q: &Point<Secp256k1>,
) -> Result<(), LindellError> {
    if pdl_w_slack_statement.ek != ek
        || pdl_w_slack_statement.ciphertext != encrypted_secret_share
        || &pdl_w_slack_statement.Q != q
    {
        return Err(LindellError::SpecificError("pdl verify failed".to_string()));
    }
    let dlog_statement = DLogStatement {
        N: pdl_w_slack_statement.N_tilde.clone(),
        g: pdl_w_slack_statement.h1.clone(),
        ni: pdl_w_slack_statement.h2.clone(),
    };
    if composite_dlog_proof.verify(&dlog_statement).is_ok()
        && pdl_w_slack_proof.verify(pdl_w_slack_statement).is_ok()
    {
        Ok(())
    } else {
        return Err(LindellError::SpecificError("pdl verify failed".to_string()));
    }
}
