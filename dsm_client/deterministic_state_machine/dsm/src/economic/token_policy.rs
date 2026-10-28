// SPDX-License-Identifier: MIT OR Apache-2.0

//! The token policy blob (SoFi §47–§51, Amendments S8 and S11): its
//! constants, its rules, and its one parser. Every reader of a policy — Core's
//! verifier, the SDK's routes, a foreign verifier — goes through
//! [`parse_token_policy`], so no two readers can disagree about one blob. The
//! one packer is the SDK's `build_policy_v3_bytes` (SoFi §47), and it parses
//! its own output here before returning it.
//!
//! Layout (all integers big-endian):
//!
//! ```text
//!   u8   version = 3
//!   u8   kind = 0 (FUNGIBLE)
//!   u8   supply_class = 0 (NATIVE)
//!   u8   flags: 0x01 burn | 0x02 transferable | 0x04 allowlist
//!   u8   release_rule: 0 all-at-creation | 1 faucet
//!   ── release rule 0 only (device-created, Amendment S8) ──
//!   32B  creator_genesis
//!   32B  creator_device_id
//!   u8   threshold k                  (1..=n)
//!   u8   signer_count n               (1..=16)
//!   n x  { u16 pk_len (> 0), pk }     (no duplicates)
//!   ── every policy ──
//!   u8   ticker_len,  ticker          (UTF-8, 2..=8 bytes)
//!   u16  alias_len,   alias           (UTF-8, not blank)
//!   u8   decimals                     (0..=18)
//!   u128 genesis_supply               (> 0)
//!   u16  description_len, description (UTF-8; empty means none)
//!   u16  icon_url_len,    icon_url    (UTF-8; empty means none)
//!   u8   allowlist_kind (0 NONE | 1 INLINE)
//!   u16  allowlist_count, count x 32B device_id
//! ```
//!
//! A network-anchored policy (release rule 1, Amendment S11) names no creator
//! and no signer set: it goes from the release rule straight to the ticker.
//! Exactly one exists, ERA's, fixed in Core; no other is registered, adopted or
//! published. The `TokenPolicyV3` wrapper must be the canonical encoding of
//! its blob, so one policy has one commitment.
//!
//! There is no minting after genesis and no unlimited supply (§48, §50). An
//! externally backed class has no specified backing-rule encoding yet (dBTC is
//! deferred), so a blob of that class is refused rather than read without it.

pub const TOKEN_POLICY_VERSION: u8 = 3;

/// Only fungible tokens exist; any other kind is a hard parse error.
pub const TOKEN_KIND_FUNGIBLE: u8 = 0;

/// The supply-class byte for a native token (SoFi §48).
pub const SUPPLY_CLASS_NATIVE: u8 = 0;

/// The supply-class byte for an externally backed token. Refused until its
/// backing rule has an encoding.
pub const SUPPLY_CLASS_EXTERNALLY_BACKED: u8 = 1;

/// The flag bits (SoFi §47, §54). Every other bit is refused.
pub const POLICY_FLAG_BURN: u8 = 0x01;
pub const POLICY_FLAG_TRANSFERABLE: u8 = 0x02;
pub const POLICY_FLAG_ALLOWLIST: u8 = 0x04;

pub const ALLOWLIST_KIND_NONE: u8 = 0;
pub const ALLOWLIST_KIND_INLINE: u8 = 1;

/// Upper bound on the signer set, so a blob cannot force unbounded work.
pub const MAX_POLICY_SIGNERS: usize = 16;

/// Ticker length in characters (SoFi §47).
pub const MIN_TICKER_LEN: usize = 2;
pub const MAX_TICKER_LEN: usize = 8;

pub const MAX_DECIMALS: u32 = 18;

/// The byte a policy blob commits for how a native token's units not yet
/// released come out (SoFi §47, §51).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseRule {
    /// The whole genesis supply is released to the creator in the transition
    /// that creates the token (device-created tokens, owner 2026-09-23).
    AllAtCreation,
    /// Units come out of the network's reserve through faucet claims (ERA in
    /// beta, Amendment S11).
    Faucet,
}

impl ReleaseRule {
    /// The byte the policy blob commits for this rule.
    pub fn code(self) -> u8 {
        match self {
            ReleaseRule::AllAtCreation => 0,
            ReleaseRule::Faucet => 1,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(ReleaseRule::AllAtCreation),
            1 => Some(ReleaseRule::Faucet),
            _ => None,
        }
    }
}

/// A native token's release rule with what it names, so a creator or a
/// signer set can be read only where the policy has one (Amendments S8, S11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Release {
    /// Device-created (Amendment S8): the whole genesis supply is released to
    /// the creator in the transition that creates the token, and only that
    /// device's `CreateToken` releases it. The signer set authorizes only what
    /// the policy's own rules name, and never issuance.
    AllAtCreation {
        /// The genesis of the device that creates the token.
        creator_genesis: [u8; 32],
        /// The creating device's id.
        creator_device_id: [u8; 32],
        /// `k` of the signer set.
        threshold: u8,
        /// `n` — the raw SPHINCS+ keys the policy names.
        signers: Vec<Vec<u8>>,
    },
    /// Network-anchored (Amendment S11): units come out of the network's
    /// reserve through faucet claims. No creating device and no signer set;
    /// the release rule alone governs every release.
    Faucet,
}

impl Release {
    /// The rule byte this release commits.
    pub fn rule(&self) -> ReleaseRule {
        match self {
            Release::AllAtCreation { .. } => ReleaseRule::AllAtCreation,
            Release::Faucet => ReleaseRule::Faucet,
        }
    }
}

/// A committed token policy, every field of the blob, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenPolicy {
    pub ticker: String,
    pub alias: String,
    pub decimals: u32,
    /// The whole supply that will ever exist, in base units.
    pub genesis_supply: u128,
    /// How units not yet released come out, and what the rule names.
    pub release: Release,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    /// Whether holders may burn. Governs burns only (§54).
    pub burn_enabled: bool,
    /// Whether the token may move between holders: checked on every transfer,
    /// vault creation and SoFi leg (§49).
    pub transferable: bool,
    /// Device ids that may receive issuance; empty when unrestricted. No
    /// market meaning: a token trades freely once issued.
    pub allowlist_device_ids: Vec<[u8; 32]>,
}

impl TokenPolicy {
    /// Whether `device_id` may receive issuance under this policy (SoFi §49,
    /// MR-SOFI-0312): anyone when the policy names no recipients, otherwise
    /// only a device it names. Issuance is the only thing the allowlist
    /// governs; no transfer, vault or market leg reads it.
    pub fn admits_issuance_to(&self, device_id: &[u8; 32]) -> bool {
        self.allowlist_device_ids.is_empty() || self.allowlist_device_ids.contains(device_id)
    }
}

/// Bounds-checked cursor; the blob must be consumed exactly.
struct Reader<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8, String> {
        let v = *self.b.get(self.off).ok_or("policy blob is truncated")?;
        self.off += 1;
        Ok(v)
    }
    fn u16be(&mut self) -> Result<usize, String> {
        let s = self.bytes(2)?;
        Ok(((s[0] as usize) << 8) | s[1] as usize)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.off.checked_add(n).ok_or("policy blob is truncated")?;
        let s = self
            .b
            .get(self.off..end)
            .ok_or("policy blob is truncated")?;
        self.off = end;
        Ok(s)
    }
    fn u128be(&mut self) -> Result<u128, String> {
        let s = self.bytes(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(s);
        Ok(u128::from_be_bytes(a))
    }
    fn utf8(&mut self, n: usize) -> Result<String, String> {
        let s = self.bytes(n)?;
        String::from_utf8(s.to_vec()).map_err(|_| "policy blob text is not UTF-8".to_string())
    }
}

/// Parse exact `TokenPolicyV3` proto bytes. The caller must already have
/// re-hashed them to the `policy_commit` it relies on: this reads a blob, it
/// does not authenticate one.
pub fn parse_token_policy(policy_proto: &[u8]) -> Result<TokenPolicy, String> {
    use prost::Message;
    let policy = crate::types::proto::TokenPolicyV3::decode(policy_proto)
        .map_err(|_| "policy proto does not decode".to_string())?;
    // One policy, one encoding. The decoder skips unknown fields and keeps the
    // last of a repeated one, so without this one blob could arrive in many
    // wrappers and so under many commitments (§47: the identity is the hash
    // of the whole policy).
    if policy.encode_to_vec() != policy_proto {
        return Err("policy proto is not the canonical encoding of its blob".into());
    }
    parse_token_policy_blob(&policy.policy_bytes)
}

/// Parse the policy blob itself.
pub fn parse_token_policy_blob(blob: &[u8]) -> Result<TokenPolicy, String> {
    let mut r = Reader { b: blob, off: 0 };

    let version = r.u8()?;
    if version != TOKEN_POLICY_VERSION {
        return Err(format!(
            "policy blob version {version} is not {TOKEN_POLICY_VERSION}"
        ));
    }
    if r.u8()? != TOKEN_KIND_FUNGIBLE {
        return Err("policy blob is not FUNGIBLE".into());
    }
    match r.u8()? {
        SUPPLY_CLASS_NATIVE => {}
        SUPPLY_CLASS_EXTERNALLY_BACKED => {
            return Err(
                "policy blob is externally backed; its backing rule has no specified \
                        encoding yet, so it is refused rather than read without one"
                    .into(),
            )
        }
        other => return Err(format!("policy blob supply class {other} is unknown")),
    }
    let flags = r.u8()?;
    if flags & !(POLICY_FLAG_BURN | POLICY_FLAG_TRANSFERABLE | POLICY_FLAG_ALLOWLIST) != 0 {
        return Err("policy blob sets a flag bit that has no meaning".into());
    }
    let rule = r.u8()?;
    let release = match ReleaseRule::from_code(rule)
        .ok_or_else(|| format!("policy blob release rule {rule} is unknown"))?
    {
        ReleaseRule::AllAtCreation => creator_and_signers(&mut r)?,
        // Network-anchored (Amendment S11): no creator and no signer set
        // follow; the next field is the ticker.
        ReleaseRule::Faucet => Release::Faucet,
    };

    let ticker_len = r.u8()? as usize;
    let ticker = r.utf8(ticker_len)?;
    // SoFi §47: a ticker is 2 to 8 characters, not bytes.
    let chars = ticker.chars().count();
    if !(MIN_TICKER_LEN..=MAX_TICKER_LEN).contains(&chars) {
        return Err(format!(
            "policy blob ticker is {chars} characters, outside {MIN_TICKER_LEN}..={MAX_TICKER_LEN}"
        ));
    }
    let alias_len = r.u16be()?;
    let alias = r.utf8(alias_len)?;
    if alias.trim().is_empty() {
        return Err("policy blob alias is blank".into());
    }
    let decimals = r.u8()? as u32;
    if decimals > MAX_DECIMALS {
        return Err(format!(
            "policy blob decimals {decimals} exceed {MAX_DECIMALS}"
        ));
    }

    // Neither class is unlimited, and a zero supply is not a token (§50).
    let genesis_supply = r.u128be()?;
    if genesis_supply == 0 {
        return Err("policy blob commits a zero genesis supply".into());
    }

    let desc_len = r.u16be()?;
    let description = Some(r.utf8(desc_len)?).filter(|s| !s.is_empty());
    let icon_len = r.u16be()?;
    let icon_url = Some(r.utf8(icon_len)?).filter(|s| !s.is_empty());

    // The committed allowlist tail: the u16 count is present in BOTH kinds,
    // and a kind-NONE blob carries an explicit zero.
    let allowlist_kind = r.u8()?;
    let allowlist_count = r.u16be()?;
    let mut allowlist_device_ids = Vec::with_capacity(allowlist_count);
    match allowlist_kind {
        ALLOWLIST_KIND_NONE => {
            if allowlist_count != 0 {
                return Err("policy blob allowlist kind NONE carries a nonzero count".into());
            }
        }
        ALLOWLIST_KIND_INLINE => {
            if allowlist_count == 0 {
                return Err("policy blob allowlist kind INLINE carries a zero count".into());
            }
            for _ in 0..allowlist_count {
                let mut d = [0u8; 32];
                d.copy_from_slice(r.bytes(32)?);
                allowlist_device_ids.push(d);
            }
        }
        _ => return Err("policy blob has an unknown allowlist kind".into()),
    }
    if (flags & POLICY_FLAG_ALLOWLIST != 0) == allowlist_device_ids.is_empty() {
        return Err("policy blob allowlist flag disagrees with its payload".into());
    }

    // Exact consumption: a padded policy would let two byte strings carry one
    // commitment.
    if r.off != blob.len() {
        return Err("policy blob has trailing bytes".into());
    }

    Ok(TokenPolicy {
        ticker,
        alias,
        decimals,
        genesis_supply,
        release,
        description,
        icon_url,
        burn_enabled: flags & POLICY_FLAG_BURN != 0,
        transferable: flags & POLICY_FLAG_TRANSFERABLE != 0,
        allowlist_device_ids,
    })
}

/// The creator (Amendment S8) and the signer set of a device-created policy.
fn creator_and_signers(r: &mut Reader<'_>) -> Result<Release, String> {
    let mut creator_genesis = [0u8; 32];
    creator_genesis.copy_from_slice(r.bytes(32)?);
    let mut creator_device_id = [0u8; 32];
    creator_device_id.copy_from_slice(r.bytes(32)?);

    let threshold = r.u8()?;
    let signer_count = r.u8()? as usize;
    if signer_count == 0 || signer_count > MAX_POLICY_SIGNERS {
        return Err(format!(
            "policy blob signer count {signer_count} is outside 1..={MAX_POLICY_SIGNERS}"
        ));
    }
    if threshold == 0 || threshold as usize > signer_count {
        return Err("policy blob threshold is not satisfiable by its own signer set".into());
    }
    let mut signers: Vec<Vec<u8>> = Vec::with_capacity(signer_count);
    for _ in 0..signer_count {
        let pk_len = r.u16be()?;
        if pk_len == 0 {
            return Err("policy blob names an empty signer key".into());
        }
        let pk = r.bytes(pk_len)?.to_vec();
        if signers.contains(&pk) {
            // One key must never satisfy a threshold above one.
            return Err("policy blob names a signer twice".into());
        }
        signers.push(pk);
    }
    Ok(Release::AllAtCreation {
        creator_genesis,
        creator_device_id,
        threshold,
        signers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    const CREATOR_GENESIS: [u8; 32] = [0x11; 32];
    const CREATOR_DEVICE: [u8; 32] = [0x22; 32];
    /// Offset of the threshold byte: five header bytes, then the creator.
    const THRESHOLD_AT: usize = 5 + 64;

    /// A well-formed device-created blob, built field by field from the
    /// layout above — not from the SDK packer, so the parser is checked
    /// against the layout.
    fn blob() -> Vec<u8> {
        created_blob(1, &[b"key".to_vec()], &tail())
    }

    /// A device-created blob with `threshold` over `signers`, then `tail`,
    /// each written as the layout lays it out.
    fn created_blob(threshold: u8, signers: &[Vec<u8>], tail: &[u8]) -> Vec<u8> {
        let mut b = vec![
            TOKEN_POLICY_VERSION,
            TOKEN_KIND_FUNGIBLE,
            SUPPLY_CLASS_NATIVE,
            POLICY_FLAG_BURN | POLICY_FLAG_TRANSFERABLE,
            ReleaseRule::AllAtCreation.code(),
        ];
        b.extend_from_slice(&CREATOR_GENESIS);
        b.extend_from_slice(&CREATOR_DEVICE);
        b.push(threshold);
        b.push(u8::try_from(signers.len()).expect("a signer count fits its byte"));
        for key in signers {
            b.extend_from_slice(
                &u16::try_from(key.len())
                    .expect("a key length fits its two bytes")
                    .to_be_bytes(),
            );
            b.extend_from_slice(key);
        }
        b.extend_from_slice(tail);
        b
    }

    /// A well-formed network-anchored blob: the release rule, then straight
    /// to the ticker (Amendment S11).
    fn network_anchored_blob() -> Vec<u8> {
        let mut b = vec![
            TOKEN_POLICY_VERSION,
            TOKEN_KIND_FUNGIBLE,
            SUPPLY_CLASS_NATIVE,
            POLICY_FLAG_BURN | POLICY_FLAG_TRANSFERABLE,
            ReleaseRule::Faucet.code(),
        ];
        b.extend_from_slice(&tail());
        b
    }

    /// Everything after the release section: ticker through allowlist.
    fn tail() -> Vec<u8> {
        tail_with("TKN", "Token", 6, 1_000_000)
    }

    /// The tail with `ticker`, `alias`, `decimals` and `supply`, and no
    /// description, icon or allowlist.
    fn tail_with(ticker: &str, alias: &str, decimals: u8, supply: u128) -> Vec<u8> {
        let mut b = vec![u8::try_from(ticker.len()).expect("a ticker length fits its byte")];
        b.extend_from_slice(ticker.as_bytes());
        b.extend_from_slice(
            &u16::try_from(alias.len())
                .expect("an alias length fits its two bytes")
                .to_be_bytes(),
        );
        b.extend_from_slice(alias.as_bytes());
        b.push(decimals);
        b.extend_from_slice(&supply.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes()); // description
        b.extend_from_slice(&0u16.to_be_bytes()); // icon
        b.push(ALLOWLIST_KIND_NONE);
        b.extend_from_slice(&0u16.to_be_bytes());
        b
    }

    /// `blob` parses; `what` names it in the failure.
    fn parses(blob: &[u8], what: &str) {
        if let Err(why) = parse_token_policy_blob(blob) {
            panic!("{what} must parse: {why}");
        }
    }

    /// The refusal `blob` meets, which must name `reason`.
    fn refused_for(blob: &[u8], reason: &str) {
        match parse_token_policy_blob(blob) {
            Err(why) => assert!(
                why.contains(reason),
                "refused, but for {why:?}, not {reason:?}"
            ),
            Ok(policy) => panic!("parsed, though it breaks {reason:?}: {policy:?}"),
        }
    }

    #[test]
    fn a_well_formed_blob_parses_to_its_fields() {
        let p = parse_token_policy_blob(&blob()).expect("parses");
        assert_eq!(
            p.release,
            Release::AllAtCreation {
                creator_genesis: CREATOR_GENESIS,
                creator_device_id: CREATOR_DEVICE,
                threshold: 1,
                signers: vec![b"key".to_vec()],
            }
        );
        assert_eq!(p.ticker, "TKN");
        assert_eq!(p.alias, "Token");
        assert_eq!(p.decimals, 6);
        assert_eq!(p.genesis_supply, 1_000_000);
        assert!(p.burn_enabled && p.transferable);
        assert!(p.description.is_none() && p.icon_url.is_none());
        assert!(p.allowlist_device_ids.is_empty());
    }

    /// Amendment S11: a network-anchored blob names no creator and no signer
    /// set, and parses to every other field as a device-created one does.
    #[test]
    fn a_network_anchored_blob_names_no_creator_and_no_signer_set() {
        let p = parse_token_policy_blob(&network_anchored_blob()).expect("parses");
        assert_eq!(p.release, Release::Faucet);
        assert_eq!(p.release.rule(), ReleaseRule::Faucet);
        assert_eq!((p.ticker.as_str(), p.alias.as_str()), ("TKN", "Token"));
        assert_eq!((p.decimals, p.genesis_supply), (6, 1_000_000));
        assert!(p.burn_enabled && p.transferable);
    }

    /// SoFi §47: a ticker is 2 to 8 characters, counted as characters, not
    /// bytes. Five letters in ten bytes parse; nine characters do not, however
    /// they are encoded, and neither does one.
    /// MUTATION CONTROL: counting bytes turns this red.
    #[test]
    fn a_ticker_is_counted_in_characters_not_bytes() {
        let with_ticker = |ticker: &str| {
            let mut b = network_anchored_blob();
            let at = 5;
            assert_eq!(
                &b[at..at + 4],
                b"\x03TKN",
                "the ticker follows the release rule"
            );
            let mut field = vec![ticker.len() as u8];
            field.extend_from_slice(ticker.as_bytes());
            b.splice(at..at + 4, field);
            b
        };
        let five = "\u{c5}\u{c4}\u{d6}\u{dc}\u{c9}";
        assert_eq!(five.len(), 10);
        let parsed = parse_token_policy_blob(&with_ticker(five)).expect("five characters parse");
        assert_eq!(parsed.ticker, five);
        for refused in [
            "\u{c5}\u{c4}\u{d6}\u{dc}\u{c9}\u{c5}\u{c4}\u{d6}\u{dc}",
            "NINELONGS",
            "X",
        ] {
            assert!(
                parse_token_policy_blob(&with_ticker(refused))
                    .is_err_and(|why| why.contains("characters")),
                "{refused:?} is refused"
            );
        }
    }

    /// A blob's shape follows its release rule: a device-created blob
    /// relabelled network-anchored reads its creator as a ticker, and a
    /// network-anchored blob relabelled device-created runs out before its
    /// creator — neither parses.
    #[test]
    fn a_blob_whose_shape_does_not_match_its_release_rule_does_not_parse() {
        let mut created_as_faucet = blob();
        created_as_faucet[4] = ReleaseRule::Faucet.code();
        assert!(parse_token_policy_blob(&created_as_faucet).is_err());

        let mut faucet_as_created = network_anchored_blob();
        faucet_as_created[4] = ReleaseRule::AllAtCreation.code();
        assert!(parse_token_policy_blob(&faucet_as_created).is_err());
    }

    /// §47: one policy, one commitment. The wrapper is the canonical encoding
    /// of its blob or it is not a policy — an unknown field, or the blob field
    /// repeated, would give the same blob another commitment.
    #[test]
    fn a_non_canonical_wrapper_does_not_parse() {
        let canonical = crate::types::proto::TokenPolicyV3 {
            policy_bytes: blob(),
        }
        .encode_to_vec();
        assert!(parse_token_policy(&canonical).is_ok());

        let mut unknown_field = canonical.clone();
        unknown_field.extend_from_slice(&[0x10, 0x01]);
        assert!(crate::types::proto::TokenPolicyV3::decode(unknown_field.as_slice()).is_ok());
        assert!(parse_token_policy(&unknown_field).is_err());

        let mut repeated = canonical.clone();
        repeated.extend_from_slice(&canonical);
        assert!(crate::types::proto::TokenPolicyV3::decode(repeated.as_slice()).is_ok());
        assert!(parse_token_policy(&repeated).is_err());
    }

    /// An edit that breaks one rule of a policy's bytes, and the reason the
    /// refusal must give: a blob refused for another rule than the one it
    /// breaks leaves that rule untested.
    type Violation = (&'static str, Box<dyn Fn(&mut Vec<u8>)>);

    #[test]
    fn every_rule_refuses_its_violation() {
        let cases: Vec<Violation> = vec![
            ("version 2 is not", Box::new(|b| b[0] = 2)),
            ("is not FUNGIBLE", Box::new(|b| b[1] = 1)),
            (
                "externally backed",
                Box::new(|b| b[2] = SUPPLY_CLASS_EXTERNALLY_BACKED),
            ),
            ("supply class 7 is unknown", Box::new(|b| b[2] = 7)),
            ("flag bit that has no meaning", Box::new(|b| b[3] |= 0x08)),
            ("release rule 9 is unknown", Box::new(|b| b[4] = 9)),
            (
                "threshold is not satisfiable",
                Box::new(|b| b[THRESHOLD_AT] = 0),
            ),
            (
                "threshold is not satisfiable",
                Box::new(|b| b[THRESHOLD_AT] = 2),
            ),
            (
                "signer count 0 is outside",
                Box::new(|b| b[THRESHOLD_AT + 1] = 0),
            ),
            ("trailing bytes", Box::new(|b| b.push(0))),
            (
                "truncated",
                Box::new(|b| {
                    b.pop();
                }),
            ),
            (
                "allowlist flag disagrees with its payload",
                Box::new(|b| b[3] |= POLICY_FLAG_ALLOWLIST),
            ),
        ];
        for (reason, edit) in cases {
            let mut b = blob();
            edit(&mut b);
            refused_for(&b, reason);
        }
    }

    /// SoFi §47 and MR-SOFI-0021: every bound the SDK's `token.create` checks
    /// before it packs a policy, Core refuses by itself, from the bytes alone.
    /// Each is taken at its edge, which parses, and one past it, which is
    /// refused naming that bound. A Core bound looser or stricter than its
    /// edge fails here whatever the SDK checks.
    ///
    /// MUTATION CONTROL: moving any one bound in `parse_token_policy_blob` or
    /// `creator_and_signers` by one (the signer count's ceiling, the
    /// threshold's, the ticker's ceiling, the decimals' ceiling), or deleting
    /// one (the zero supply, the blank alias, the empty key, the repeated
    /// key), turns this red.
    #[test]
    fn each_bound_parses_at_its_edge_and_is_refused_one_past_it() {
        let key = |i: usize| format!("key-{i}").into_bytes();
        let keys = |n: usize| (0..n).map(key).collect::<Vec<_>>();

        // The signer set: 1 to MAX_POLICY_SIGNERS keys.
        for n in [1, MAX_POLICY_SIGNERS] {
            parses(
                &created_blob(1, &keys(n), &tail()),
                &format!("{n} signers parse"),
            );
        }
        refused_for(
            &created_blob(1, &keys(MAX_POLICY_SIGNERS + 1), &tail()),
            &format!("signer count {} is outside", MAX_POLICY_SIGNERS + 1),
        );

        // The threshold: 1 to the signer count.
        let three = keys(3);
        parses(
            &created_blob(3, &three, &tail()),
            "a threshold of the whole set parses",
        );
        refused_for(
            &created_blob(4, &three, &tail()),
            "threshold is not satisfiable",
        );

        // Every key is a key, and none counts twice toward the threshold.
        refused_for(
            &created_blob(1, &[key(0), Vec::new()], &tail()),
            "empty signer key",
        );
        refused_for(
            &created_blob(2, &[key(0), key(0)], &tail()),
            "names a signer twice",
        );

        // The ticker: 2 to 8 characters.
        for ticker in ["TK", "TKNTKNTK"] {
            parses(
                &created_blob(1, &keys(1), &tail_with(ticker, "Token", 6, 1)),
                &format!("the ticker {ticker:?} parses"),
            );
        }
        refused_for(
            &created_blob(1, &keys(1), &tail_with("TKNTKNTKN", "Token", 6, 1)),
            "9 characters",
        );

        // The alias: any non-blank text.
        parses(
            &created_blob(1, &keys(1), &tail_with("TKN", "T", 6, 1)),
            "a one-letter alias parses",
        );
        refused_for(
            &created_blob(1, &keys(1), &tail_with("TKN", "   ", 6, 1)),
            "alias is blank",
        );

        // The decimals: 0 to MAX_DECIMALS.
        let most = u8::try_from(MAX_DECIMALS).expect("the most decimals fit their byte");
        parses(
            &created_blob(1, &keys(1), &tail_with("TKN", "Token", most, 1)),
            &format!("{most} decimals parse"),
        );
        refused_for(
            &created_blob(1, &keys(1), &tail_with("TKN", "Token", most + 1, 1)),
            &format!("decimals {} exceed", most + 1),
        );

        // The supply: at least one base unit.
        parses(
            &created_blob(1, &keys(1), &tail_with("TKN", "Token", 6, 1)),
            "a supply of one unit parses",
        );
        refused_for(
            &created_blob(1, &keys(1), &tail_with("TKN", "Token", 6, 0)),
            "zero genesis supply",
        );
    }

    /// §50: a zero supply is not a token.
    #[test]
    fn a_zero_genesis_supply_is_refused() {
        refused_for(
            &created_blob(1, &[b"key".to_vec()], &tail_with("TKN", "Token", 6, 0)),
            "zero genesis supply",
        );
    }

    #[test]
    fn release_rule_codes_round_trip() {
        for rule in [ReleaseRule::AllAtCreation, ReleaseRule::Faucet] {
            assert_eq!(ReleaseRule::from_code(rule.code()), Some(rule));
        }
        assert_eq!(ReleaseRule::from_code(2), None);
    }
}
