use std::fs;
use std::path::{Path, PathBuf};

use dsm::crypto::ephemeral_key::{
    derive_ephemeral_seed, derive_kyber_step_key, generate_ephemeral_keypair,
    verify_cdbrw_response_signature,
};
use dsm::crypto::kyber::{kyber_decapsulate, KyberKeyPair};
use dsm::types::error::DsmError;

const VERIFIER_KEYPAIR_FILE: &str = "cdbrw_verifier_kyber_v1.bin";

#[derive(Debug, Clone, PartialEq)]
pub struct CdbrwVerificationOutcome {
    pub accepted: bool,
    pub reason: &'static str,
    pub gamma_distance: f32,
    pub threshold: f32,
}

impl CdbrwVerificationOutcome {
    pub fn accepted(gamma_distance: f32, threshold: f32) -> Self {
        Self {
            accepted: true,
            reason: "accepted",
            gamma_distance,
            threshold,
        }
    }

    pub fn rejected(reason: &'static str, gamma_distance: f32, threshold: f32) -> Self {
        Self {
            accepted: false,
            reason,
            gamma_distance,
            threshold,
        }
    }
}

pub struct CdbrwVerificationRequest<'a> {
    pub binding_key: &'a [u8; 32],
    pub challenge: &'a [u8],
    pub gamma: &'a [u8; 32],
    pub ciphertext: &'a [u8],
    pub signature: &'a [u8],
    pub supplied_ephemeral_public_key: &'a [u8],
    pub chain_tip: &'a [u8; 32],
    pub commitment_preimage: &'a [u8; 32],
    pub enrollment_anchor: &'a [u8; 32],
    pub epsilon_intra: f32,
    pub epsilon_inter: f32,
}

fn verifier_keypair_path_from_base(base_dir: &Path) -> PathBuf {
    base_dir.join(VERIFIER_KEYPAIR_FILE)
}

fn write_verifier_keypair(path: &Path, keypair: &KyberKeyPair) -> Result<(), DsmError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            DsmError::storage(format!("create verifier key dir {parent:?}: {e}"), Some(e))
        })?;
    }
    fs::write(path, keypair.to_bytes())
        .map_err(|e| DsmError::storage(format!("write verifier keypair {path:?}: {e}"), Some(e)))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(path)
            .map_err(|e| {
                DsmError::storage(format!("stat verifier keypair {path:?}: {e}"), Some(e))
            })?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms).map_err(|e| {
            DsmError::storage(format!("chmod verifier keypair {path:?}: {e}"), Some(e))
        })?;
    }
    Ok(())
}

fn read_verifier_keypair(path: &Path) -> Result<KyberKeyPair, DsmError> {
    let bytes = fs::read(path)
        .map_err(|e| DsmError::storage(format!("read verifier keypair {path:?}: {e}"), Some(e)))?;
    KyberKeyPair::from_bytes(&bytes)
}

pub fn ensure_verifier_keypair_at(base_dir: &Path) -> Result<KyberKeyPair, DsmError> {
    let path = verifier_keypair_path_from_base(base_dir);
    if path.exists() {
        return read_verifier_keypair(&path);
    }
    let keypair = KyberKeyPair::generate()?;
    write_verifier_keypair(&path, &keypair)?;
    Ok(keypair)
}

pub fn ensure_verifier_public_key() -> Result<Vec<u8>, DsmError> {
    let base_dir = crate::storage_utils::ensure_storage_base_dir()?;
    let keypair = ensure_verifier_keypair_at(&base_dir)?;
    Ok(keypair.public_key.clone())
}

pub fn read_verifier_public_key_if_present() -> Result<Option<Vec<u8>>, DsmError> {
    let base_dir = crate::storage_utils::ensure_storage_base_dir()?;
    let path = verifier_keypair_path_from_base(&base_dir);
    if !path.exists() {
        return Ok(None);
    }
    let keypair = read_verifier_keypair(&path)?;
    Ok(Some(keypair.public_key.clone()))
}

pub fn verify_challenge_response_with_keypair(
    verifier_keypair: &KyberKeyPair,
    request: &CdbrwVerificationRequest<'_>,
) -> Result<CdbrwVerificationOutcome, DsmError> {
    let shared_secret = kyber_decapsulate(&verifier_keypair.secret_key, request.ciphertext)?;
    let k_step = derive_kyber_step_key(&shared_secret);
    let expected_seed = derive_ephemeral_seed(
        request.chain_tip,
        request.commitment_preimage,
        &k_step,
        request.binding_key,
    );
    let (expected_ephemeral_public_key, _) = generate_ephemeral_keypair(&expected_seed)?;

    if request.supplied_ephemeral_public_key != expected_ephemeral_public_key.as_slice() {
        return Ok(CdbrwVerificationOutcome::rejected(
            "ephemeral_key_mismatch",
            0.0,
            0.0,
        ));
    }

    if !verify_cdbrw_response_signature(
        &expected_ephemeral_public_key,
        request.gamma,
        request.ciphertext,
        request.challenge,
        request.signature,
    )? {
        return Ok(CdbrwVerificationOutcome::rejected(
            "signature_invalid",
            0.0,
            0.0,
        ));
    }

    let threshold = (request.epsilon_intra + request.epsilon_inter) / 2.0f32;
    let mut distance = 0.0f32;
    for (lhs, rhs) in request.gamma.iter().zip(request.enrollment_anchor.iter()) {
        let diff = (*lhs as i32) - (*rhs as i32);
        distance += (diff * diff) as f32;
    }
    distance = distance.sqrt() / 256.0f32;

    if threshold > 0.0f32 && distance > threshold {
        return Ok(CdbrwVerificationOutcome::rejected(
            "gamma_distance_exceeded",
            distance,
            threshold,
        ));
    }

    Ok(CdbrwVerificationOutcome::accepted(distance, threshold))
}

pub fn verify_challenge_response(
    request: &CdbrwVerificationRequest<'_>,
) -> Result<CdbrwVerificationOutcome, DsmError> {
    let base_dir = crate::storage_utils::ensure_storage_base_dir()?;
    let keypair = ensure_verifier_keypair_at(&base_dir)?;
    verify_challenge_response_with_keypair(&keypair, request)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use dsm::crypto::ephemeral_key::{derive_kyber_coins, sign_cdbrw_response_with_context};
    use dsm::crypto::kyber::kyber_encapsulate_deterministic;

    use super::*;

    #[test]
    fn ensure_verifier_keypair_round_trip_at_path() {
        let temp_dir = TempDir::new().expect("tempdir");
        let first = ensure_verifier_keypair_at(temp_dir.path()).expect("first keypair");
        let second = ensure_verifier_keypair_at(temp_dir.path()).expect("second keypair");
        assert_eq!(first.public_key, second.public_key);
        assert_eq!(first.secret_key, second.secret_key);
    }

    #[test]
    fn verify_challenge_response_accepts_valid_response() {
        let verifier_keypair = KyberKeyPair::generate().expect("verifier keypair");
        let binding_key = [0x11; 32];
        let chain_tip = [0x22; 32];
        let commitment_preimage = [0x33; 32];
        let device_id = [0x44; 32];
        let challenge = vec![0x55; 32];
        let gamma = [0x66; 32];

        let coins = derive_kyber_coins(&chain_tip, &commitment_preimage, &device_id, &binding_key);
        let (shared_secret, ciphertext) =
            kyber_encapsulate_deterministic(&verifier_keypair.public_key, &coins)
                .expect("encapsulate");
        let k_step = derive_kyber_step_key(&shared_secret);
        let (signature, ephemeral_public_key) = sign_cdbrw_response_with_context(
            &chain_tip,
            &commitment_preimage,
            &k_step,
            &binding_key,
            &gamma,
            &ciphertext,
            &challenge,
        )
        .expect("sign");

        let request = CdbrwVerificationRequest {
            binding_key: &binding_key,
            challenge: &challenge,
            gamma: &gamma,
            ciphertext: &ciphertext,
            signature: &signature,
            supplied_ephemeral_public_key: &ephemeral_public_key,
            chain_tip: &chain_tip,
            commitment_preimage: &commitment_preimage,
            enrollment_anchor: &gamma,
            epsilon_intra: 0.0,
            epsilon_inter: 0.0,
        };

        let outcome =
            verify_challenge_response_with_keypair(&verifier_keypair, &request).expect("verify");

        assert_eq!(outcome, CdbrwVerificationOutcome::accepted(0.0, 0.0));
    }

    #[test]
    fn verify_challenge_response_rejects_wrong_ephemeral_key() {
        let verifier_keypair = KyberKeyPair::generate().expect("verifier keypair");
        let binding_key = [0x11; 32];
        let chain_tip = [0x22; 32];
        let commitment_preimage = [0x33; 32];
        let device_id = [0x44; 32];
        let challenge = vec![0x55; 32];
        let gamma = [0x66; 32];

        let coins = derive_kyber_coins(&chain_tip, &commitment_preimage, &device_id, &binding_key);
        let (shared_secret, ciphertext) =
            kyber_encapsulate_deterministic(&verifier_keypair.public_key, &coins)
                .expect("encapsulate");
        let k_step = derive_kyber_step_key(&shared_secret);
        let (signature, mut ephemeral_public_key) = sign_cdbrw_response_with_context(
            &chain_tip,
            &commitment_preimage,
            &k_step,
            &binding_key,
            &gamma,
            &ciphertext,
            &challenge,
        )
        .expect("sign");
        ephemeral_public_key[0] ^= 0x01;

        let request = CdbrwVerificationRequest {
            binding_key: &binding_key,
            challenge: &challenge,
            gamma: &gamma,
            ciphertext: &ciphertext,
            signature: &signature,
            supplied_ephemeral_public_key: &ephemeral_public_key,
            chain_tip: &chain_tip,
            commitment_preimage: &commitment_preimage,
            enrollment_anchor: &gamma,
            epsilon_intra: 0.0,
            epsilon_inter: 0.0,
        };

        let outcome =
            verify_challenge_response_with_keypair(&verifier_keypair, &request).expect("verify");

        assert_eq!(
            outcome,
            CdbrwVerificationOutcome::rejected("ephemeral_key_mismatch", 0.0, 0.0)
        );
    }
}
