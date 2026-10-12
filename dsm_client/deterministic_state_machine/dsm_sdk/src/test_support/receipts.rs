// SPDX-License-Identifier: Apache-2.0

//! Real receipts for SDK tests of receipt artifacts — signing, verification,
//! splitting, budgets. An identity is the Genesis v3 a wallet derives from the
//! mnemonic over `[seed; 32]` ([`test_mnemonic`](crate::economic_fixtures::test_mnemonic));
//! a step is made by Core's advance; its receipt is built by the one producer
//! ([`StitchedReceiptV2::of_step`]); an answer is the per-step EK derived the
//! way [`sign_receipt_with_per_step_ek`](crate::sdk::receipts::sign_receipt_with_per_step_ek)
//! derives it, keyed by the identity's own `Smaster`.
//!
//! The steps are Core's: the sender's ERA is its faucet claim at the Core
//! layer, with no admission and no device storage behind it. These fixtures
//! are for tests of what a receipt carries and proves; a test of value on the
//! device path funds through [`crate::economic_fixtures`].

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use dsm::core::bilateral_transaction_manager::{compute_precommit, compute_smt_key};
use dsm::core::identity::genesis_v3::{derive_genesis_v3_self_attested, GenesisV3};
use dsm::core::token::token_state_manager::era_policy_commit;
use dsm::crypto::ephemeral_key;
use dsm::economic::register::BETA_NETWORK_ID;
use dsm::types::device_state::{AdvanceOutcome, BalanceDelta, BalanceDirection, DeviceState};
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::receipt_types::{DeviceTreeAcceptanceCommitment, StitchedReceiptV2};
use dsm::types::token_types::Balance;

/// A wallet's identity, derived from its mnemonic.
pub struct Party {
    v3: GenesisV3,
    kyber_public_key: Vec<u8>,
}

/// One per-step EK answer: the EK, the prior key's certificate over it, the
/// EK's signature over the response target, and the ML-KEM ciphertext the
/// EK's derivation consumed.
pub struct StepAnswer {
    pub ek_pk: Vec<u8>,
    pub ek_cert: Vec<u8>,
    pub sig: Vec<u8>,
    pub kyber_ct: Vec<u8>,
}

impl Party {
    /// The identity the wallet created from the mnemonic over `[seed; 32]`
    /// has on the beta network.
    pub fn from_seed(seed: u8) -> Self {
        let wallet_seed = bip39::Mnemonic::parse(crate::economic_fixtures::test_mnemonic(seed))
            .expect("the test mnemonic parses")
            .to_seed("");
        let v3 = derive_genesis_v3_self_attested(
            &wallet_seed,
            BETA_NETWORK_ID,
            0,
            0,
            3,
            &dsm::core::identity::genesis_v2::genesis_authority_policy_hash(),
        )
        .expect("genesis v3 from the wallet seed");
        let (kyber_public_key, _) =
            dsm::crypto::kyber::generate_kyber_identity_keypair(&v3.smaster)
                .expect("the ML-KEM key from Smaster");
        Self {
            v3,
            kyber_public_key,
        }
    }

    /// `G`.
    pub fn genesis(&self) -> [u8; 32] {
        self.v3.g
    }

    /// `DevID`.
    pub fn device_id(&self) -> [u8; 32] {
        self.v3.devid
    }

    /// The AK's public half.
    pub fn signing_public_key(&self) -> &[u8] {
        &self.v3.ak_public
    }

    /// The AK's secret half.
    pub fn signing_secret_key(&self) -> &[u8] {
        &self.v3.ak_secret
    }

    /// The ML-KEM public key the identity derives from `Smaster`.
    pub fn kyber_public_key(&self) -> &[u8] {
        &self.kyber_public_key
    }

    /// The device head at genesis.
    pub fn head(&self) -> DeviceState {
        DeviceState::new(
            self.genesis(),
            self.device_id(),
            self.signing_public_key().to_vec(),
        )
    }

    /// The Device Tree commitment of this identity's one device.
    pub fn device_tree_commitment(&self) -> DeviceTreeAcceptanceCommitment {
        DeviceTreeAcceptanceCommitment::from_root(
            dsm::common::device_tree::DeviceTree::single(self.device_id()).root(),
        )
    }

    /// An online transfer of `amount` ERA to `receiver` from the relationship
    /// tip `h_n`, shaped and signed as `wallet.send` shapes and signs one.
    pub fn era_transfer(&self, receiver: &Party, h_n: &[u8; 32], amount: u64) -> Operation {
        let token_id = b"ERA".to_vec();
        let to_device_id = receiver.device_id();
        let nonce = {
            let mut hasher =
                dsm::crypto::blake3::dsm_domain_hasher(dsm::common::domain_tags::TAG_DSM_NONCE);
            hasher.update(h_n);
            hasher.update(&amount.to_le_bytes());
            hasher.update(&token_id);
            hasher.update(&to_device_id);
            hasher.finalize().as_bytes().to_vec()
        };
        let unsigned = |signature: Vec<u8>| Operation::Transfer {
            to_device_id: to_device_id.to_vec(),
            amount: Balance::amount(amount),
            policy_commit: era_policy_commit(),
            terms_commitment: dsm::types::operations::TransferTerms {
                token_id: token_id.clone(),
                nonce: nonce.clone(),
                mode: TransactionMode::Unilateral,
                memo: String::new(),
                salt: vec![0x5A; 32],
            }
            .commitment(),
            signature,
            authority_policy: None,
        };
        let signature = dsm::crypto::sphincs::sphincs_sign(
            self.signing_secret_key(),
            &unsigned(Vec::new()).to_bytes(),
        )
        .expect("the AK signs the transfer");
        unsigned(signature)
    }

    /// This party's per-step EK answer on its relationship with `toward`, at
    /// its tip `h_n` for the step precommitted as `c_pre`, over `target`, with
    /// its AK as the prior key (a relationship's first step).
    pub fn answer(
        &self,
        toward: &Party,
        h_n: &[u8; 32],
        c_pre: &[u8; 32],
        target: &[u8; 32],
    ) -> StepAnswer {
        let recipient_kem_pub_hash = dsm::crypto::blake3::domain_hash_bytes(
            dsm::common::domain_tags::TAG_DSM_KYBER_RECIPIENT_PUB_V1,
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
        let (shared_secret, kyber_ct) =
            dsm::crypto::kyber::kyber_encapsulate_deterministic(toward.kyber_public_key(), &coins)
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
        let sig = dsm::crypto::sphincs::sphincs_sign(&ek_sk, target).expect("the EK answers");
        StepAnswer {
            ek_pk,
            ek_cert,
            sig,
            kyber_ct,
        }
    }
}

/// One step and its receipt.
pub struct Step {
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
/// ERA, drawn from the sender's first faucet payout at the Core layer.
pub fn transfer_step(sender: &Party, receiver: &Party, amount: u64) -> Step {
    let me = sender.device_id();
    let head = sender
        .head()
        .advance(
            compute_smt_key(&me, &me),
            me,
            Operation::FaucetClaim {
                reserve_id: dsm::economic::native_reserve::era_reserve_id(BETA_NETWORK_ID),
                generation: 1,
            },
            &[BalanceDelta {
                policy_commit: era_policy_commit(),
                direction: BalanceDirection::Credit,
                amount: dsm::economic::native_reserve::ERA_FAUCET_PAYOUT,
            }],
            None,
            None,
        )
        .expect("the faucet payout")
        .new_device_state
        .establish_relationship(receiver.device_id())
        .expect("the relationship is established");
    let h_n = head
        .chain_tip(&compute_smt_key(&me, &receiver.device_id()))
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

/// `sender`'s first `count` steps toward `receiver`: online transfers of
/// `amount` ERA each, every step from the tip the step before it left.
pub fn transfer_chain(sender: &Party, receiver: &Party, amount: u64, count: usize) -> Vec<Step> {
    let rel_key = compute_smt_key(&sender.device_id(), &receiver.device_id());
    let mut steps = vec![transfer_step(sender, receiver, amount)];
    while steps.len() < count {
        let head = steps
            .last()
            .expect("the chain has a step")
            .outcome
            .new_device_state
            .clone();
        let h_n = head
            .chain_tip(&rel_key)
            .expect("the relationship has a tip");
        let operation = sender.era_transfer(receiver, &h_n, amount);
        steps.push(step(
            sender,
            receiver,
            head,
            operation,
            BalanceDirection::Debit,
            amount,
        ));
    }
    steps
}
