// SPDX-License-Identifier: MIT OR Apache-2.0

//! Real steps for tests. An identity is Genesis v3 derived from a wallet
//! seed on the beta network, exactly as a wallet derives it; a step is made
//! by the real advance; its receipt is built by the one producer
//! ([`StitchedReceiptV2::of_step`]); a signature is the per-step EK answer
//! derived the way the SDK's per-step signer derives it (§11). The seeds are
//! the only typed-in inputs: every id, key, tip, root, path, entropy and
//! signature is derived from them.

use crate::common::device_tree::DeviceTree;
use crate::core::bilateral_transaction_manager::{compute_precommit, compute_smt_key};
use crate::core::identity::genesis_v2::genesis_authority_policy_hash;
use crate::core::identity::genesis_v3::{derive_genesis_v3_self_attested, GenesisV3};
use crate::core::token::token_state_manager::era_policy_commit;
use crate::crypto::ephemeral_key;
use crate::economic::register::BETA_NETWORK_ID;
use crate::types::device_state::{AdvanceOutcome, BalanceDelta, BalanceDirection, DeviceState};
use crate::types::operations::{Operation, TransactionMode};
use crate::types::receipt_types::{DeviceTreeAcceptanceCommitment, StitchedReceiptV2};
use crate::types::token_types::Balance;

/// A wallet's identity, derived from its seed.
pub(crate) struct Party {
    v3: GenesisV3,
    kyber_public_key: Vec<u8>,
}

/// One per-step EK answer: the EK the step derived, the prior key's
/// certificate over it, the EK's signature over the response target, and the
/// ML-KEM ciphertext the EK's derivation consumed.
pub(crate) struct StepAnswer {
    pub ek_pk: Vec<u8>,
    pub ek_cert: Vec<u8>,
    pub sig: Vec<u8>,
    pub kyber_ct: Vec<u8>,
}

impl Party {
    /// The identity a wallet with this seed has on the beta network.
    pub(crate) fn from_seed(seed: &[u8]) -> Self {
        let v3 = derive_genesis_v3_self_attested(
            seed,
            BETA_NETWORK_ID,
            0,
            0,
            3,
            &genesis_authority_policy_hash(),
        )
        .expect("genesis v3 from the seed");
        let (kyber_public_key, _) =
            crate::crypto::kyber::generate_kyber_keypair_from_entropy(&v3.smaster, "DSM/kyber\0")
                .expect("the ML-KEM key from Smaster");
        Self {
            v3,
            kyber_public_key,
        }
    }

    /// `G`.
    pub(crate) fn genesis(&self) -> [u8; 32] {
        self.v3.g
    }

    /// `DevID`.
    pub(crate) fn device_id(&self) -> [u8; 32] {
        self.v3.devid
    }

    /// The AK's public half.
    pub(crate) fn signing_public_key(&self) -> &[u8] {
        &self.v3.ak_public
    }

    /// The AK's secret half.
    pub(crate) fn signing_secret_key(&self) -> &[u8] {
        &self.v3.ak_secret
    }

    /// The ML-KEM public key the identity derives from `Smaster`.
    pub(crate) fn kyber_public_key(&self) -> &[u8] {
        &self.kyber_public_key
    }

    /// The device head at genesis.
    pub(crate) fn head(&self) -> DeviceState {
        DeviceState::new(
            self.genesis(),
            self.device_id(),
            self.signing_public_key().to_vec(),
        )
    }

    /// The Device Tree commitment of this identity's one device.
    pub(crate) fn device_tree_commitment(&self) -> DeviceTreeAcceptanceCommitment {
        DeviceTreeAcceptanceCommitment::from_root(DeviceTree::single(self.device_id()).root())
    }

    /// An online transfer of `amount` ERA to `receiver`, from the relationship
    /// tip `h_n`, shaped and signed as `wallet.send` shapes and signs one: the
    /// nonce is `BLAKE3("DSM/nonce\0" ‖ h_n ‖ amount ‖ token_id ‖ recipient)`,
    /// and the signature is the AK's over the operation with its signature
    /// cleared.
    pub(crate) fn era_transfer(&self, receiver: &Party, h_n: &[u8; 32], amount: u64) -> Operation {
        let token_id = b"ERA".to_vec();
        let to_device_id = receiver.device_id();
        let nonce = {
            let mut hasher =
                crate::crypto::blake3::dsm_domain_hasher(crate::common::domain_tags::TAG_DSM_NONCE);
            hasher.update(h_n);
            hasher.update(&amount.to_le_bytes());
            hasher.update(&token_id);
            hasher.update(&to_device_id);
            hasher.finalize().as_bytes().to_vec()
        };
        let unsigned = |signature: Vec<u8>| Operation::Transfer {
            to_device_id: to_device_id.to_vec(),
            amount: Balance::amount(amount),
            token_id: token_id.clone(),
            policy_commit: era_policy_commit(),
            mode: TransactionMode::Unilateral,
            nonce: nonce.clone(),
            recipient: receiver.signing_public_key().to_vec(),
            to: crate::utils::text_id::encode_base32_crockford(&to_device_id).into_bytes(),
            message: String::new(),
            signature,
            authority_policy: None,
        };
        let signature = crate::crypto::sphincs::sphincs_sign(
            self.signing_secret_key(),
            &unsigned(Vec::new()).to_bytes(),
        )
        .expect("the AK signs the transfer");
        unsigned(signature)
    }

    /// This party's per-step EK answer on its relationship with `toward`, at
    /// its tip `h_n` for the step precommitted as `c_pre`, over `target` —
    /// derived as the SDK's per-step signer derives it on a relationship's
    /// first step, where the AK is the prior key: ML-KEM coins from `Smaster`,
    /// a deterministic encapsulation to `toward`'s key, `k_step` from the
    /// shared secret, the EK from `Smaster` and `k_step`, and the AK's
    /// certificate over the EK at `h_n`.
    pub(crate) fn answer(
        &self,
        toward: &Party,
        h_n: &[u8; 32],
        c_pre: &[u8; 32],
        target: &[u8; 32],
    ) -> StepAnswer {
        let recipient_kem_pub_hash = crate::crypto::blake3::domain_hash_bytes(
            crate::common::domain_tags::TAG_DSM_KYBER_RECIPIENT_PUB_V1,
            toward.kyber_public_key(),
        );
        let coins = ephemeral_key::derive_kyber_coins(
            &self.v3.smaster,
            ephemeral_key::KYBER_ALG_ID_MLKEM768,
            &recipient_kem_pub_hash,
            h_n,
            c_pre,
            &self.device_id(),
        );
        let (shared_secret, kyber_ct) = crate::crypto::kyber::kyber_encapsulate_deterministic(
            toward.kyber_public_key(),
            &coins,
        )
        .expect("the encapsulation to the counterparty's key");
        let k_step = ephemeral_key::derive_kyber_step_key(&shared_secret);
        let seed = ephemeral_key::derive_ephemeral_seed(
            &self.v3.smaster,
            ephemeral_key::ALG_ID_SPX256F,
            &compute_smt_key(&self.device_id(), &toward.device_id()),
            h_n,
            c_pre,
            &k_step,
        );
        let (ek_pk, ek_sk) =
            ephemeral_key::generate_ephemeral_keypair(&seed).expect("the per-step EK");
        let ek_cert = ephemeral_key::sign_ek_cert(self.signing_secret_key(), &ek_pk, h_n)
            .expect("the AK certifies the EK");
        let sig = crate::crypto::sphincs::sphincs_sign(&ek_sk, target).expect("the EK answers");
        StepAnswer {
            ek_pk,
            ek_cert,
            sig,
            kyber_ct,
        }
    }
}

/// One step and its receipt.
pub(crate) struct Step {
    pub operation: Operation,
    pub outcome: AdvanceOutcome,
    pub receipt: StitchedReceiptV2,
    /// `C_pre`: the step's precommitment over its tip, its operation with the
    /// signature cleared, and its one entropy.
    pub c_pre: [u8; 32],
}

fn step(
    author: &Party,
    toward: &Party,
    head: DeviceState,
    operation: Operation,
    direction: BalanceDirection,
    amount: u64,
) -> Step {
    let rel_key = compute_smt_key(&author.device_id(), &toward.device_id());
    let h_n = head
        .chain_tip(&rel_key)
        .expect("the established relationship has a tip");
    let outcome = head
        .advance(
            rel_key,
            toward.device_id(),
            operation.clone(),
            &[BalanceDelta {
                policy_commit: era_policy_commit(),
                direction,
                amount,
            }],
            None,
            None,
        )
        .expect("the step");
    let receipt = StitchedReceiptV2::of_step(
        author.genesis(),
        author.device_id(),
        toward.device_id(),
        &outcome,
        None,
        &author.device_tree_commitment(),
    )
    .expect("the step's receipt");
    let c_pre = compute_precommit(
        &h_n,
        &operation.with_cleared_signature().to_bytes(),
        &outcome.transition_entropy(),
    );
    Step {
        operation,
        outcome,
        receipt,
        c_pre,
    }
}

/// `sender`'s first step toward `receiver`: an online transfer of `amount`
/// ERA, drawn from the sender's first faucet payout.
pub(crate) fn transfer_step(sender: &Party, receiver: &Party, amount: u64) -> Step {
    let head = sender
        .head()
        .admitted_faucet_claim(1)
        .expect("the faucet payout")
        .establish_relationship(receiver.device_id())
        .expect("the relationship is established");
    let h_n = head
        .chain_tip(&compute_smt_key(&sender.device_id(), &receiver.device_id()))
        .expect("the established relationship has a tip");
    let operation = sender.era_transfer(receiver, &h_n, amount);
    step(
        sender,
        receiver,
        head,
        operation,
        BalanceDirection::Debit,
        amount,
    )
}

/// `receiver`'s first step toward `sender`: its credit of `operation`, the
/// transfer `sender` made to it.
pub(crate) fn credit_step(receiver: &Party, sender: &Party, operation: &Operation) -> Step {
    let Operation::Transfer { amount, .. } = operation else {
        panic!("a credit step credits a transfer");
    };
    let head = receiver
        .head()
        .establish_relationship(sender.device_id())
        .expect("the relationship is established");
    step(
        receiver,
        sender,
        head,
        operation.clone(),
        BalanceDirection::Credit,
        amount.value(),
    )
}
