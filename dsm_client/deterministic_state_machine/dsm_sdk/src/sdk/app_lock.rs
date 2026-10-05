// SPDX-License-Identifier: MIT OR Apache-2.0

//! The app lock: what opens the wallet on this device, and how many wrong
//! tries it has left. Rust is its only authority. The PIN or button pattern is
//! enrolled here as an Argon2id hash and checked here; each miss is counted
//! and stored before the wrong try is answered; after the third miss no PIN or
//! pattern is checked at all until the wallet's recovery phrase is, which
//! resets the count. Nothing here reads a clock (ci/no_clock_and_no_json.sh):
//! what ends the misses is the phrase, not a wait.
//!
//! The frontend only sends what the user entered and renders what the session
//! snapshot reports. It reads none of this module's settings: the preferences
//! route refuses every key in [`OWNED_KEYS`].

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use dsm::types::error::DsmError;
use subtle::ConstantTimeEq;

use crate::sdk::app_state::AppState;

/// The Argon2id hash (PHC string) of the enrolled PIN or pattern; empty when
/// none is enrolled.
const CREDENTIAL_KEY: &str = "lock_credential";
/// The wrong tries since the last opening.
const MISSES_KEY: &str = "lock_misses";

/// Wrong tries before only the recovery phrase opens the lock.
pub const MISSES_BEFORE_PHRASE: u32 = 3;

/// Every setting the lock keeps, here and in the session manager. No one but
/// Rust reads or writes them.
pub const OWNED_KEYS: [&str; 6] = [
    CREDENTIAL_KEY,
    MISSES_KEY,
    "lock_enabled",
    "lock_method",
    "lock_on_pause",
    "lock_locked",
];

fn refuse(what: impl Into<String>) -> DsmError {
    DsmError::invalid_operation(what.into())
}

/// How the wallet is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMethod {
    Pin,
    Combo,
}

impl LockMethod {
    pub fn parse(method: &str) -> Result<Self, DsmError> {
        match method {
            "pin" => Ok(Self::Pin),
            "combo" => Ok(Self::Combo),
            other => Err(refuse(format!(
                "the lock method {other:?} is neither \"pin\" nor \"combo\""
            ))),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Pin => "pin",
            Self::Combo => "combo",
        }
    }

    /// What is hashed: the method's domain, then the secret, so a PIN never
    /// opens a pattern lock that happens to spell the same text.
    fn input(self, secret: &str) -> Vec<u8> {
        let domain: &[u8] = match self {
            Self::Pin => b"DSM/app-lock/pin/v1",
            Self::Combo => b"DSM/app-lock/combo/v1",
        };
        let mut out = Vec::with_capacity(domain.len() + 1 + secret.len());
        out.extend_from_slice(domain);
        out.push(0);
        out.extend_from_slice(secret.as_bytes());
        out
    }
}

/// The enrolled credential, if one is.
fn credential() -> Option<String> {
    AppState::get_pref(CREDENTIAL_KEY).filter(|stored| !stored.is_empty())
}

/// Whether a PIN or pattern is enrolled.
pub fn enrolled() -> bool {
    credential().is_some()
}

/// The wrong tries since the last opening. A stored count that is not a
/// number is an error, never read as none.
pub fn misses() -> Result<u32, DsmError> {
    match AppState::get_pref(MISSES_KEY).as_deref() {
        None | Some("") => Ok(0),
        Some(stored) => stored
            .parse::<u32>()
            .map_err(|e| DsmError::InvalidState(format!("the lock's miss count {stored:?}: {e}"))),
    }
}

fn set_misses(count: u32) -> Result<(), DsmError> {
    AppState::set_pref(MISSES_KEY, &count.to_string())
}

/// Enroll `secret` as what opens the lock by `method`: its Argon2id hash under
/// a fresh salt replaces any earlier one, and the miss count starts again.
pub fn enroll(method: LockMethod, secret: &str) -> Result<(), DsmError> {
    if secret.is_empty() {
        return Err(refuse("a lock needs its PIN or pattern"));
    }
    let mut salt = [0u8; 16];
    rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut salt)
        .map_err(|e| DsmError::crypto(format!("lock salt: {e}"), None::<std::io::Error>))?;
    let salt = SaltString::encode_b64(&salt)
        .map_err(|e| DsmError::crypto(format!("lock salt: {e}"), None::<std::io::Error>))?;
    let hash = Argon2::default()
        .hash_password(&method.input(secret), &salt)
        .map_err(|e| DsmError::crypto(format!("lock hash: {e}"), None::<std::io::Error>))?
        .to_string();
    AppState::set_pref(CREDENTIAL_KEY, &hash)?;
    set_misses(0)
}

/// Forget the enrolled PIN or pattern and the miss count.
pub fn clear() -> Result<(), DsmError> {
    AppState::set_pref(CREDENTIAL_KEY, "")?;
    set_misses(0)
}

/// What a try at the lock came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tried {
    Opened,
    /// Wrong; `left` tries remain before only the phrase opens it.
    Wrong {
        left: u32,
    },
    /// No PIN or pattern is checked: the tries are used up, or none is
    /// enrolled. Only the recovery phrase opens the lock.
    PhraseRequired,
}

/// Try `secret` against the lock enrolled for `method`. A miss is stored
/// before it is answered, so ending the app between the two loses nothing.
pub fn try_secret(method: LockMethod, secret: &str) -> Result<Tried, DsmError> {
    let missed = misses()?;
    if missed >= MISSES_BEFORE_PHRASE {
        return Ok(Tried::PhraseRequired);
    }
    let Some(stored) = credential() else {
        return Ok(Tried::PhraseRequired);
    };
    let enrolled = PasswordHash::new(&stored).map_err(|e| {
        DsmError::InvalidState(format!("the lock's enrolled hash does not parse: {e}"))
    })?;
    match Argon2::default().verify_password(&method.input(secret), &enrolled) {
        Ok(()) => {
            set_misses(0)?;
            Ok(Tried::Opened)
        }
        Err(argon2::password_hash::Error::Password) => {
            let now = missed + 1;
            set_misses(now)?;
            Ok(match MISSES_BEFORE_PHRASE.checked_sub(now) {
                Some(left) if left > 0 => Tried::Wrong { left },
                Some(..) | None => Tried::PhraseRequired,
            })
        }
        Err(e) => Err(DsmError::crypto(
            format!("lock check: {e}"),
            None::<std::io::Error>,
        )),
    }
}

/// What a try with the recovery phrase came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhraseTried {
    Opened,
    NotThisWallet,
}

/// Try `phrase`: it opens the lock exactly when it derives this wallet's seed,
/// compared in constant time with the seed the wallet holds, and then the
/// miss count starts again. A wrong phrase is not counted: guessing a phrase
/// is not a short search.
pub fn try_phrase(phrase: &str) -> Result<PhraseTried, DsmError> {
    let mnemonic = bip39::Mnemonic::parse(phrase.trim())
        .map_err(|e| refuse(format!("that is not a recovery phrase: {e}")))?;
    let held =
        crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed().ok_or_else(|| {
            DsmError::InvalidState(
                "the wallet's seed is not loaded, so no phrase can be compared with it".to_string(),
            )
        })?;
    let derived = mnemonic.to_seed("");
    if bool::from(derived.as_slice().ct_eq(held.as_slice())) {
        set_misses(0)?;
        Ok(PhraseTried::Opened)
    } else {
        Ok(PhraseTried::NotThisWallet)
    }
}
