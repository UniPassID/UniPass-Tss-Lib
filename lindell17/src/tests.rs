#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use crate::{
        keygen::{li17_p1_key_gen1, li17_p1_key_gen2, li17_p2_key_gen1, li17_p2_key_gen2},
        sign::{li17_p1_sign1, li17_p1_sign2, li17_p2_sign1, li17_p2_sign2},
    };

    #[test]
    fn sign() {
        // keygen
        let (context1p1, msg1p1) = li17_p1_key_gen1().unwrap();

        let (context1p2, msg1p2) = li17_p2_key_gen1(msg1p1).unwrap();

        let (sign_context_p1, msg2p1) = li17_p1_key_gen2(context1p1, msg1p2).unwrap();

        let (sign_context_p2, _pk) = li17_p2_key_gen2(context1p2, msg2p1).unwrap();

        // sign
        let mut hasher = Sha256::new();
        hasher.update(b"random message");
        let hash = hasher.finalize().to_vec();

        let (context1p2, smsg1p2) = li17_p2_sign1(sign_context_p2, &hash).unwrap();

        let (context1p1, smsg1p1) = li17_p1_sign1(sign_context_p1, smsg1p2, &hash).unwrap();

        let smsg2p2 = li17_p2_sign2(context1p2, smsg1p1).unwrap();

        let _sig = li17_p1_sign2(context1p1, smsg2p2).unwrap();
    }
}
