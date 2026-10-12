// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cross-check the real DSM wrapper digests against Lean's byte builders.
use std::{fs, path::PathBuf};
use super::ephemeral_key;

fn blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn case(
    dir: &std::path::Path,
    op: u8,
    fields: [&[u8]; 3],
    specification: (&str, &[u8], &[u8; 32]),
) -> Result<(), Box<dyn std::error::Error>> {
    let [pk, sk, msg] = fields;
    let (tag, payload, expected) = specification;
    let mut input = tag.as_bytes().to_vec();
    input.push(0);
    input.extend_from_slice(payload);
    let mode = if sk.is_empty() { 4 } else { 1 };
    let digest = if sk.is_empty() {
        ::blake3::hash(&input)
    } else {
        ::blake3::keyed_hash(sk.try_into()?, &input)
    };
    assert_eq!(
        digest.as_bytes(),
        expected,
        "real wrapper agrees with byte specification"
    );
    let mut out = b"DSPX2\0".to_vec();
    out.extend_from_slice(&[5, op, 2]);
    for field in [pk, sk, msg, &expected[..]] {
        blob(&mut out, field);
    }
    out.extend_from_slice(&1u32.to_be_bytes());
    out.push(mode);
    for field in [&[][..], sk, &input[..], &expected[..]] {
        blob(&mut out, field);
    }
    fs::write(dir.join(format!("wrapper-{op}.bin")), out)?;
    Ok(())
}
#[test]
fn export_wrapper_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let requested = std::env::var("DSM_SPHINCS_VECTOR_DIR");
    let dir = match &requested {
        Ok(path) => PathBuf::from(path),
        Err(std::env::VarError::NotPresent) => {
            std::env::temp_dir().join(format!("dsm-wrapper-refinement-{}", std::process::id()))
        }
        Err(e) => return Err(format!("vector directory: {e}").into()),
    };
    fs::create_dir_all(&dir)?;
    let pk = [11u8; 64];
    let tip = [22u8; 32];
    let att = [33u8; 32];
    let device = [44u8; 32];
    let genesis = [55u8; 32];
    let kem = [66u8; 1184];
    let master = [77u8; 32];
    let pre = [88u8; 32];
    let step = [99u8; 32];
    case(
        &dir,
        3,
        [&pk, &[], &tip],
        (
            "DSM/ek-cert",
            &[&pk[..], &tip].concat(),
            &ephemeral_key::derive_ek_cert_hash(&pk, &tip),
        ),
    )?;
    let fields = [&device[..], &tip, &pre, &step].concat();
    let alg = ephemeral_key::ALG_ID_SPX256F;
    case(
        &dir,
        4,
        [alg, &master, &fields],
        (
            "DSM/ek/v1",
            &[alg, &fields].concat(),
            &ephemeral_key::derive_ephemeral_seed(&master, alg, &device, &tip, &pre, &step),
        ),
    )?;
    case(
        &dir,
        5,
        [&pk, &[], &att],
        (
            "DSM/devid",
            &[&pk[..], &att].concat(),
            &crate::core::identity::genesis_v2::derive_devid(&pk, &att),
        ),
    )?;
    let fields = [&device[..], &genesis].concat();
    case(
        &dir,
        6,
        [&kem, &[], &fields],
        (
            "DSM/kyber-identity-binding",
            &[&fields[..], &kem].concat(),
            &crate::bilateral::identity_binding::binding_digest(&device, &genesis, &kem),
        ),
    )?;
    if matches!(requested, Err(std::env::VarError::NotPresent)) {
        fs::remove_dir_all(&dir)?;
    }
    Ok(())
}
