// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test-only primitive transcripts for the independent Lean control flow.
use super::*;
use std::{cell::RefCell, fs, path::PathBuf};

#[derive(Clone)]
struct Call {
    mode: u8,
    context: String,
    key: Vec<u8>,
    input: Vec<u8>,
    output: Vec<u8>,
}
thread_local! {
    static ACTIVE: RefCell<Option<Vec<Call>>> = const { RefCell::new(None) };
}
pub(super) fn record(mode: u8, context: &str, key: &[u8], input: &[u8], output: &[u8]) {
    ACTIVE.with(|active| {
        if let Some(calls) = active.borrow_mut().as_mut() {
            calls.push(Call {
                mode,
                context: context.into(),
                key: key.to_vec(),
                input: input.to_vec(),
                output: output.to_vec(),
            });
        }
    });
}
fn capture<T>(f: impl FnOnce() -> T) -> Result<(T, Vec<Call>), &'static str> {
    ACTIVE.with(|a| *a.borrow_mut() = Some(Vec::new()));
    let result = f();
    let calls = ACTIVE
        .with(|a| a.borrow_mut().take())
        .ok_or("capture recorder disappeared")?;
    Ok((result, calls))
}
fn blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn write_case(
    dir: &std::path::Path,
    name: &str,
    header: [u8; 3],
    fields: [&[u8]; 4],
    calls: Vec<Call>,
) -> std::io::Result<()> {
    let [variant, op, expected] = header;
    let [pk, sk, msg, sig] = fields;
    let mut out = b"DSPX2\0".to_vec();
    out.extend_from_slice(&[variant, op, expected]);
    for data in [pk, sk, msg, sig] {
        blob(&mut out, data);
    }
    out.extend_from_slice(&(calls.len() as u32).to_be_bytes());
    for call in calls {
        out.push(call.mode);
        blob(&mut out, call.context.as_bytes());
        blob(&mut out, &call.key);
        blob(&mut out, &call.input);
        blob(&mut out, &call.output);
    }
    fs::write(dir.join(format!("{name}.bin")), out)
}

#[test]
fn export_refinement_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let requested = std::env::var("DSM_SPHINCS_VECTOR_DIR");
    let dir = match &requested {
        Ok(path) => PathBuf::from(path),
        Err(std::env::VarError::NotPresent) => {
            std::env::temp_dir().join(format!("dsm-sphincs-refinement-{}", std::process::id()))
        }
        Err(e) => return Err(format!("vector directory: {e}").into()),
    };
    fs::create_dir_all(&dir)?;
    for (id, v) in [(1, SphincsVariant::SPX128f), (5, SphincsVariant::SPX256f)] {
        let seed = [0xD5; 32];
        let msg = b"DSM SPHINCS+ construction vector";
        let (kp, calls) = capture(|| generate_keypair_from_seed(v, &seed))?;
        let kp = kp.map_err(|e| format!("keygen: {e:?}"))?;
        write_case(
            &dir,
            &format!("{id}-keygen"),
            [id, 2, 2],
            [&kp.public_key, &kp.secret_key, &seed, &[]],
            calls,
        )?;
        let (sig, calls) = capture(|| sign(v, &kp.secret_key, msg))?;
        let sig = sig.map_err(|e| format!("sign: {e:?}"))?;
        write_case(
            &dir,
            &format!("{id}-sign"),
            [id, 1, 2],
            [&kp.public_key, &kp.secret_key, msg, &sig],
            calls,
        )?;
        let (ok, calls) = capture(|| verify(v, &kp.public_key, msg, &sig))?;
        assert!(ok.map_err(|e| format!("verify: {e:?}"))?);
        write_case(
            &dir,
            &format!("{id}-verify"),
            [id, 0, 2],
            [&kp.public_key, &[], msg, &sig],
            calls,
        )?;
        let mut damaged = sig.clone();
        damaged[param_set(v).n] ^= 1;
        let (ok, calls) = capture(|| verify(v, &kp.public_key, msg, &damaged))?;
        assert!(!ok.map_err(|e| format!("verify damaged: {e:?}"))?);
        write_case(
            &dir,
            &format!("{id}-damaged"),
            [id, 0, 1],
            [&kp.public_key, &[], msg, &damaged],
            calls,
        )?;
        for (name, bad_msg, bad_pk, bad_sig, expected) in [
            ("empty-message", &[][..], &kp.public_key[..], &sig[..], 0),
            ("short-pk", &msg[..], &kp.public_key[1..], &sig[..], 1),
            ("short-sig", &msg[..], &kp.public_key[..], &sig[1..], 1),
        ] {
            let (result, calls) = capture(|| verify(v, bad_pk, bad_msg, bad_sig))?;
            match result {
                Err(Error::Crypto(why)) => {
                    assert_eq!(expected, 0);
                    assert_eq!(why, CryptoFailure::EmptyVerificationMessage);
                }
                Ok(valid) => {
                    assert_eq!(expected, 1);
                    assert!(!valid);
                }
            }
            write_case(
                &dir,
                &format!("{id}-{name}"),
                [id, 0, expected],
                [bad_pk, &[], bad_msg, bad_sig],
                calls,
            )?;
        }
    }
    let mut rng = ChaCha20Rng::from_seed([45u8; 32]);
    for (id, variant) in [
        SphincsVariant::SPX128s,
        SphincsVariant::SPX128f,
        SphincsVariant::SPX192s,
        SphincsVariant::SPX192f,
        SphincsVariant::SPX256s,
        SphincsVariant::SPX256f,
    ]
    .into_iter()
    .enumerate()
    {
        let p = param_set(variant);
        for sample in 0..16 {
            let mut message = vec![0u8; p.n];
            let mut digest = vec![0u8; p.m];
            rng.fill_bytes(&mut message);
            rng.fill_bytes(&mut digest);
            if sample == 0 {
                digest.fill(0);
            }
            if sample == 1 {
                digest.fill(u8::MAX);
            }
            let tree = rng.next_u64();
            let mut address = Adrs::new();
            let layer = rng.next_u32();
            let address_tree = rng.next_u64();
            let kind = rng.next_u32() % 7;
            let keypair = rng.next_u32();
            let chain_index = rng.next_u32();
            let hash_index = rng.next_u32();
            address.set_layer(layer);
            address.set_tree(address_tree);
            address.set_type_and_clear(kind);
            address.set_keypair(keypair);
            address.set_chain(chain_index);
            address.set_hash(hash_index);
            let mut input = message.clone();
            input.extend_from_slice(&digest);
            input.extend_from_slice(&tree.to_be_bytes());
            input.extend_from_slice(&layer.to_be_bytes());
            input.extend_from_slice(&address_tree.to_be_bytes());
            for word in [kind, keypair, chain_index, hash_index] {
                input.extend_from_slice(&word.to_be_bytes());
            }
            let mut parameter_bytes = Vec::new();
            for field in [
                p.n,
                p.h,
                p.d,
                p.a,
                p.k,
                p.hp,
                p.len,
                p.md_bytes,
                p.tree_bytes,
                p.leaf_bytes,
                p.m,
                p.pk_bytes,
                p.sk_bytes,
                p.sig_bytes,
            ] {
                parameter_bytes.extend_from_slice(&(field as u32).to_be_bytes());
            }
            let mut expected_bytes = Vec::new();
            for digit in wots_digits(&p, &message) {
                expected_bytes.extend_from_slice(&digit.to_be_bytes());
            }
            let indices = split_digest(&p, &digest);
            expected_bytes.extend_from_slice(&indices.idx_tree.to_be_bytes());
            expected_bytes.extend_from_slice(&indices.idx_leaf.to_be_bytes());
            let (leaf, next) = next_layer(&p, tree);
            expected_bytes.extend_from_slice(&leaf.to_be_bytes());
            expected_bytes.extend_from_slice(&next.to_be_bytes());
            for digit in base_2b(&digest, p.a, p.k) {
                expected_bytes.extend_from_slice(&digit.to_be_bytes());
            }
            write_case(
                &dir,
                &format!("utility-{id}-{sample}"),
                [id as u8, 7, 2],
                [
                    &parameter_bytes,
                    &address.as_bytes(),
                    &input,
                    &expected_bytes,
                ],
                Vec::new(),
            )?;
        }
    }
    if matches!(requested, Err(std::env::VarError::NotPresent)) {
        fs::remove_dir_all(&dir)?;
    }
    Ok(())
}
