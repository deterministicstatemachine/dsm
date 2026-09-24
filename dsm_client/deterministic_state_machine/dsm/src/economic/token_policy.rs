// SPDX-License-Identifier: MIT OR Apache-2.0

//! The token policy blob (SoFi §47–§51): its constants, its rules, and its one
//! parser. Every reader of a policy — Core's verifier, the SDK's routes, a
//! foreign verifier — goes through [`parse_token_policy`], so no two readers
//! can disagree about one blob. The one packer is the SDK's
//! `build_policy_v3_bytes` (SoFi §47), and it parses its own output here
//! before returning it.
//!
//! Layout (all integers big-endian):
//!
//! ```text
//!   u8   version = 3
//!   u8   kind = 0 (FUNGIBLE)
//!   u8   supply_class = 0 (NATIVE)
//!   u8   flags: 0x01 burn | 0x02 transferable | 0x04 allowlist
//!   u8   release_rule: 0 all-at-creation | 1 faucet
//!   32B  creator_genesis              (SoFi Amendment S8)
//!   32B  creator_device_id
//!   u8   threshold k                  (1..=n)
//!   u8   signer_count n               (1..=16)
//!   n x  { u16 pk_len (> 0), pk }     (no duplicates)
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

/// Ticker length in bytes.
pub const MIN_TICKER_LEN: usize = 2;
pub const MAX_TICKER_LEN: usize = 8;

pub const MAX_DECIMALS: u32 = 18;

/// How a native token's units not yet released come out (SoFi §47, §51). A
/// named rule of the token's committed policy: every release is a transition
/// the constructor builds under it, and anyone recomputes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseRule {
    /// The whole genesis supply is released to the creator in the transition
    /// that creates the token (user-created tokens in beta, owner 2026-09-23).
    AllAtCreation,
    /// Units come out of the token's reserve through faucet claims (ERA in
    /// beta). An emission schedule replaces it later as another rule over the
    /// same release path.
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

/// A committed token policy, every field of the blob, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenPolicy {
    /// The genesis of the device that creates the token. Only that device's
    /// `CreateToken` releases a native token's supply (SoFi Amendment S8).
    pub creator_genesis: [u8; 32],
    /// The creating device's id.
    pub creator_device_id: [u8; 32],
    pub ticker: String,
    pub alias: String,
    pub decimals: u32,
    /// The whole supply that will ever exist, in base units.
    pub genesis_supply: u128,
    /// How units not yet released come out.
    pub release_rule: ReleaseRule,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    /// Whether holders may burn. Governs burns only (§54).
    pub burn_enabled: bool,
    /// Whether the token may move between holders: checked on every transfer,
    /// vault creation and SoFi leg (§49).
    pub transferable: bool,
    /// `k` of the signer set. The set authorizes only what the policy's own
    /// rules name, and never issuance.
    pub threshold: u8,
    /// `n` — the raw SPHINCS+ keys the policy names.
    pub signers: Vec<Vec<u8>>,
    /// Device ids that may receive issuance; empty when unrestricted. No
    /// market meaning: a token trades freely once issued.
    pub allowlist_device_ids: Vec<[u8; 32]>,
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
    let release_rule = ReleaseRule::from_code(rule)
        .ok_or_else(|| format!("policy blob release rule {rule} is unknown"))?;
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

    let ticker_len = r.u8()? as usize;
    let ticker = r.utf8(ticker_len)?;
    if ticker.len() < MIN_TICKER_LEN || ticker.len() > MAX_TICKER_LEN {
        return Err(format!(
            "policy blob ticker is {} bytes, outside {MIN_TICKER_LEN}..={MAX_TICKER_LEN}",
            ticker.len()
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
        creator_genesis,
        creator_device_id,
        ticker,
        alias,
        decimals,
        genesis_supply,
        release_rule,
        description,
        icon_url,
        burn_enabled: flags & POLICY_FLAG_BURN != 0,
        transferable: flags & POLICY_FLAG_TRANSFERABLE != 0,
        threshold,
        signers,
        allowlist_device_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREATOR_GENESIS: [u8; 32] = [0x11; 32];
    const CREATOR_DEVICE: [u8; 32] = [0x22; 32];
    /// Offset of the threshold byte: five header bytes, then the creator.
    const THRESHOLD_AT: usize = 5 + 64;

    /// A well-formed blob, built field by field from the layout above — not
    /// from the SDK packer, so the parser is checked against the layout.
    fn blob() -> Vec<u8> {
        let mut b = vec![
            TOKEN_POLICY_VERSION,
            TOKEN_KIND_FUNGIBLE,
            SUPPLY_CLASS_NATIVE,
            POLICY_FLAG_BURN | POLICY_FLAG_TRANSFERABLE,
            ReleaseRule::AllAtCreation.code(),
        ];
        b.extend_from_slice(&CREATOR_GENESIS);
        b.extend_from_slice(&CREATOR_DEVICE);
        b.push(1); // threshold
        b.push(1); // signers
        b.extend_from_slice(&3u16.to_be_bytes());
        b.extend_from_slice(b"key");
        b.push(3);
        b.extend_from_slice(b"TKN");
        b.extend_from_slice(&5u16.to_be_bytes());
        b.extend_from_slice(b"Token");
        b.push(6); // decimals
        b.extend_from_slice(&1_000_000u128.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes()); // description
        b.extend_from_slice(&0u16.to_be_bytes()); // icon
        b.push(ALLOWLIST_KIND_NONE);
        b.extend_from_slice(&0u16.to_be_bytes());
        b
    }

    #[test]
    fn a_well_formed_blob_parses_to_its_fields() {
        let p = parse_token_policy_blob(&blob()).expect("parses");
        assert_eq!(
            (p.creator_genesis, p.creator_device_id),
            (CREATOR_GENESIS, CREATOR_DEVICE)
        );
        assert_eq!(p.ticker, "TKN");
        assert_eq!(p.alias, "Token");
        assert_eq!(p.decimals, 6);
        assert_eq!(p.genesis_supply, 1_000_000);
        assert_eq!(p.release_rule, ReleaseRule::AllAtCreation);
        assert!(p.burn_enabled && p.transferable);
        assert_eq!((p.threshold, p.signers.len()), (1, 1));
        assert!(p.description.is_none() && p.icon_url.is_none());
        assert!(p.allowlist_device_ids.is_empty());
    }

    /// A named edit that breaks one rule of a policy's bytes.
    type Violation = (&'static str, Box<dyn Fn(&mut Vec<u8>)>);

    #[test]
    fn every_rule_refuses_its_violation() {
        let cases: Vec<Violation> = vec![
            ("version", Box::new(|b| b[0] = 2)),
            ("kind", Box::new(|b| b[1] = 1)),
            (
                "externally backed",
                Box::new(|b| b[2] = SUPPLY_CLASS_EXTERNALLY_BACKED),
            ),
            ("unknown class", Box::new(|b| b[2] = 7)),
            ("meaningless flag", Box::new(|b| b[3] |= 0x08)),
            ("unknown release rule", Box::new(|b| b[4] = 9)),
            ("zero threshold", Box::new(|b| b[THRESHOLD_AT] = 0)),
            ("threshold above n", Box::new(|b| b[THRESHOLD_AT] = 2)),
            ("zero signers", Box::new(|b| b[THRESHOLD_AT + 1] = 0)),
            ("trailing byte", Box::new(|b| b.push(0))),
            (
                "truncated",
                Box::new(|b| {
                    b.pop();
                }),
            ),
            (
                "allowlist flag without payload",
                Box::new(|b| b[3] |= POLICY_FLAG_ALLOWLIST),
            ),
        ];
        for (why, edit) in cases {
            let mut b = blob();
            edit(&mut b);
            assert!(
                parse_token_policy_blob(&b).is_err(),
                "{why} must be refused"
            );
        }
    }

    #[test]
    fn a_zero_genesis_supply_is_refused() {
        let mut b = blob();
        // header (5) + creator (64) + threshold and n (2) + pk (2 + 3)
        // + ticker (1 + 3) + alias (2 + 5) + decimals (1)
        let at = THRESHOLD_AT + 2 + 5 + 4 + 7 + 1;
        b[at..at + 16].copy_from_slice(&0u128.to_be_bytes());
        assert!(parse_token_policy_blob(&b).is_err());
    }

    #[test]
    fn release_rule_codes_round_trip() {
        for rule in [ReleaseRule::AllAtCreation, ReleaseRule::Faucet] {
            assert_eq!(ReleaseRule::from_code(rule.code()), Some(rule));
        }
        assert_eq!(ReleaseRule::from_code(2), None);
    }
}
