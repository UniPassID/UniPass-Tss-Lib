#[cfg(test)]
mod tests {

    use curv::elliptic::curves::{Point, Scalar, Secp256k1};
    use sha2::{Digest, Sha256};

    use crate::{
        keygen::{li17_p1_key_gen1, li17_p1_key_gen2, li17_p2_key_gen1, li17_p2_key_gen2},
        keyrecover::{li17_p1_key_recover1, li17_p2_key_recover1, li17_p2_key_recover2},
        li17_p2_exract_secret,
        refresh::{li17_p1_refresh1, li17_p1_refresh2, li17_p2_refresh1},
        selfkeygen::{li17_p1_key_generate1, li17_p1_key_generate2, li17_p2_key_generate1},
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

    #[test]
    fn refresh() {
        // keygen
        let (context1p1, msg1p1) = li17_p1_key_gen1().unwrap();

        let (context1p2, msg1p2) = li17_p2_key_gen1(msg1p1).unwrap();

        let (sign_context_p1, msg2p1) = li17_p1_key_gen2(context1p1, msg1p2).unwrap();

        let (sign_context_p2, _pk) = li17_p2_key_gen2(context1p2, msg2p1).unwrap();

        // refresh
        let (refresh_context_1, rmsg1p1) = li17_p1_refresh1(sign_context_p1).unwrap();

        let (sign_context_p2, _x_3, rmsg1p2) = li17_p2_refresh1(sign_context_p2, rmsg1p1).unwrap();

        let sign_context_p1 = li17_p1_refresh2(refresh_context_1, rmsg1p2).unwrap();

        // sign
        let mut hasher = Sha256::new();
        hasher.update(b"random message");
        let hash = hasher.finalize().to_vec();

        let (context1p2, smsg1p) = li17_p2_sign1(sign_context_p2, &hash).unwrap();

        let (context1p1, smsg1p1) = li17_p1_sign1(sign_context_p1, smsg1p, &hash).unwrap();

        let smsg2p2 = li17_p2_sign2(context1p2, smsg1p1).unwrap();

        let _sig = li17_p1_sign2(context1p1, smsg2p2).unwrap();
    }

    #[test]
    fn generate() {
        // generate

        let (context_p1, msg1p1) = li17_p1_key_generate1().unwrap();
        let (sign_context_p2, _x_3, msg1p2) = li17_p2_key_generate1(msg1p1).unwrap();

        let sign_context_p1 = li17_p1_key_generate2(context_p1, msg1p2).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(b"random message");
        let hash = hasher.finalize().to_vec();

        let (context1p2, smsg1p) = li17_p2_sign1(sign_context_p2, &hash).unwrap();

        let (context1p1, smsg1p1) = li17_p1_sign1(sign_context_p1, smsg1p, &hash).unwrap();

        let smsg2p2 = li17_p2_sign2(context1p2, smsg1p1).unwrap();

        let _sig = li17_p1_sign2(context1p1, smsg2p2).unwrap();
    }

    #[test]
    fn recover() {
        // generate

        let (context_p1, msg1p1) = li17_p1_key_generate1().unwrap();
        let (sign_context_p2, x_3_raw, msg1p2) = li17_p2_key_generate1(msg1p1).unwrap();

        let sign_context_p1 = li17_p1_key_generate2(context_p1, msg1p2).unwrap();

        println!("{:?}", x_3_raw);

        let public_3 = &x_3_raw * Point::<Secp256k1>::generator();
        if public_3
            != Scalar::<Secp256k1>::from(2) * &sign_context_p1.public_p2
                - &sign_context_p1.public_p1
        {
            todo!();
        }

        let x_2_raw = li17_p2_exract_secret(&sign_context_p2).unwrap();

        println!("x_2_raw: {:?}", x_2_raw);

        let (context_p2, msg1p2) = li17_p2_key_recover1(x_2_raw.clone(), 3).unwrap();

        let msg1p1 = li17_p1_key_recover1(sign_context_p1.clone(), msg1p2).unwrap();

        let x_3 = li17_p2_key_recover2(
            context_p2,
            msg1p1,
            &[&sign_context_p2.public_p1, &sign_context_p2.public_p2],
        )
        .unwrap();

        assert!(x_3 == x_3_raw);

        let (context_p2, msg1p2) = li17_p2_key_recover1(x_3_raw, 2).unwrap();

        let msg1p1 = li17_p1_key_recover1(sign_context_p1, msg1p2).unwrap();

        let x_2 =
            li17_p2_key_recover2(context_p2, msg1p1, &[&sign_context_p2.public_p1, &public_3])
                .unwrap();

        println!("x_2: {:?}", x_2);
        assert!(x_2 == x_2_raw);
    }

    // #[test]
    // fn test_serialize() {
    //     let (context_p1, msg1p1) = li17_p1_key_generate1().unwrap();
    //     let (_sign_context_p2, x_3_raw, msg1p2) = li17_p2_key_generate1(msg1p1).unwrap();

    //     let sign_context_p1 = li17_p1_key_generate2(context_p1, msg1p2).unwrap();

    //     let up_key = EncryptedUPKey::new(
    //         sqlx::types::Uuid::from_u128(126),
    //         "".to_string(),
    //         &sign_context_p1,
    //     )
    //     .unwrap();

    //     let _sign_context: Li17SignP1Context = up_key.try_into().unwrap();
    // }

    #[test]
    fn test_fib() {
        let n: u64 = 100;

        let c = if n == 1 {
            0
        } else if n == 2 {
            1
        } else if n == 3 {
            1
        } else {
            let mut previous: u128 = 1; // 2nd
            let mut new: u128 = 1; // 3rd
            let mut ghost: u128;
            let mut runner: u64 = 4;

            while runner < n {
                ghost = new;
                new = previous + new;
                previous = ghost;
                runner += 1;
            }

            new + previous
        };

        println!("c: {}", c);
    }
}
