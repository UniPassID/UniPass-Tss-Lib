#[cfg(test)]
mod tests {
    use curv::elliptic::curves::{Ed25519, Point};
    use ed25519_dalek::Verifier;
    use itertools::Itertools;
    use multi_party_eddsa::protocols::Signature;

    use crate::{
        keygen::{keygen_phase1, keygen_phase2, keygen_phase3, keygen_phase4},
        sign::{sign_phase1, sign_phase2, sign_phase3, sign_phase4, sign_phase5},
    };

    pub fn verify_dalek(pk: &Point<Ed25519>, sig: &Signature, msg: &[u8]) -> bool {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&*sig.R.to_bytes(true));
        sig_bytes[32..].copy_from_slice(&sig.s.to_bytes());

        let dalek_pub = ed25519_dalek::PublicKey::from_bytes(&*pk.to_bytes(true)).unwrap();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes).unwrap();

        dalek_pub.verify(msg, &dalek_sig).is_ok()
    }

    #[test]
    fn test_tss() {
        let t = 2;
        let n = 5;

        let (context1, msgs1): (Vec<_>, Vec<_>) = (0..n)
            .into_iter()
            .map(|index| keygen_phase1(t, n, index + 1).unwrap())
            .unzip();
        let (context2, msgs2): (Vec<_>, Vec<_>) = (0..n)
            .into_iter()
            .map(|index| keygen_phase2(context1[index as usize].clone(), msgs1.clone()).unwrap())
            .unzip();
        let (context3, msgs3): (Vec<_>, Vec<_>) = (0..n)
            .into_iter()
            .map(|index| keygen_phase3(context2[index as usize].clone(), msgs2.clone()).unwrap())
            .unzip();

        let sign_keys: Vec<_> = (0..n)
            .into_iter()
            .map(|index| {
                keygen_phase4(
                    context3[index as usize].clone(),
                    (0..n)
                        .into_iter()
                        .map(|j| msgs3[j as usize][index as usize].clone())
                        .collect(),
                )
                .unwrap()
            })
            .collect();

        let message = [12u8, 34, 45, 76, 35];

        for group in (1u16..=n).combinations(usize::from(t + 1)) {
            let group_indexs: Vec<_> = group.iter().map(|a| a - 1).collect();

            let (sign_context1, sign_msg1): (Vec<_>, Vec<_>) = group_indexs
                .iter()
                .map(|&i| sign_phase1(&sign_keys[i as usize], group.clone(), &message).unwrap())
                .unzip();

            let (sign_context2, sign_msg2): (Vec<_>, Vec<_>) = group_indexs
                .iter()
                .enumerate()
                .map(|(index, &i)| {
                    sign_phase2(
                        &sign_keys[i as usize],
                        sign_context1[index].clone(),
                        sign_msg1.clone(),
                    )
                    .unwrap()
                })
                .unzip();
            let (sign_context3, sign_msg3): (Vec<_>, Vec<_>) = group_indexs
                .iter()
                .enumerate()
                .map(|(index, &i)| {
                    sign_phase3(
                        &sign_keys[i as usize],
                        sign_context2[index].clone(),
                        sign_msg2.clone(),
                    )
                    .unwrap()
                })
                .unzip();

            let (sign_context4, sign_msg4): (Vec<_>, Vec<_>) = group_indexs
                .iter()
                .enumerate()
                .map(|(index, &i)| {
                    sign_phase4(
                        &sign_keys[i as usize],
                        sign_context3[index].clone(),
                        (0..t + 1)
                            .into_iter()
                            .map(|j| sign_msg3[j as usize][index as usize].clone())
                            .collect(),
                    )
                    .unwrap()
                })
                .unzip();

            let sigs: Vec<_> = group_indexs
                .iter()
                .enumerate()
                .map(|(index, &i)| {
                    sign_phase5(
                        &sign_keys[i as usize],
                        sign_context4[index].clone(),
                        sign_msg4.clone(),
                    )
                    .unwrap()
                })
                .collect_vec();

            sigs.into_iter().for_each(|sig| {
                let ok = verify_dalek(&sign_keys[0].agg_pubkey, &sig, &message);
                if !ok {
                    panic!("verify failed");
                } else {
                    println!("verify success!");
                }
            });
        }
    }

    #[test]
    fn test_serialize() {
        let t = 1;
        let n = 3;

        let (context1, msgs1): (Vec<_>, Vec<_>) = (0..n)
            .into_iter()
            .map(|index| keygen_phase1(t, n, index + 1).unwrap())
            .unzip();
        let (context2, msgs2): (Vec<_>, Vec<_>) = (0..n)
            .into_iter()
            .map(|index| keygen_phase2(context1[index as usize].clone(), msgs1.clone()).unwrap())
            .unzip();
        let (context3, msgs3): (Vec<_>, Vec<_>) = (0..n)
            .into_iter()
            .map(|index| keygen_phase3(context2[index as usize].clone(), msgs2.clone()).unwrap())
            .unzip();

        let sign_keys: Vec<_> = (0..n)
            .into_iter()
            .map(|index| {
                keygen_phase4(
                    context3[index as usize].clone(),
                    (0..n)
                        .into_iter()
                        .map(|j| msgs3[j as usize][index as usize].clone())
                        .collect(),
                )
                .unwrap()
            })
            .collect();

        let ss = base64::encode(serde_json::to_string(&sign_keys[0].secret_share).unwrap());
        let vss = serde_json::to_string(&sign_keys[0].vss_schemes).unwrap();
        let pk = base64::encode(&sign_keys[0].agg_pubkey.to_bytes(true).as_ref());
        println!("{}, {}, {}", ss.len(), vss.len(), pk.len())
    }
}
