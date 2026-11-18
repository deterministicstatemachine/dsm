//! The owner's stamp on a board (DSM Amendment A38, owner, 2026-11-18).
//!
//! The owner sets up every board before it ships. His boot key is burned and the board locked, so it
//! runs only firmware he signed, and the board seals its own secret itself, when it is told to, so its
//! partition key `pk_host` exists only inside it. He then signs the board's public identity — its
//! `anchor_id`, `pk_host` and the chip's resident key `pk_chip` — with his stamp key. That signature is
//! the board's stamp, and the board keeps it.
//!
//! A receiver admits a board only when the board's stamp verifies under the stamp key the wallet
//! carries, and a receiving board refuses a payment from a board whose stamp does not verify under the
//! same key in its own firmware. A board made by anyone else has no stamp: its keys were never signed,
//! and a stamp taken from a real board names that board's identity, not its own.
//!
//! The stamp is in the scheme of the key it vouches for, `pk_host`: BLAKE3-SPHINCS+ SPX128f. A stronger
//! stamp would add nothing a payment relies on, since every release is signed under `pk_host` itself,
//! and it would not fit beside `σ^host` in a payment check the board can hold.

use crate::domain::BOARD_STAMP_V1;
use crate::enrollment::commit;
use crate::hash::h;
use crate::tropic::HostSig;

/// The length of a stamp: one SPX128f signature.
pub const BOARD_STAMP_BYTES: usize = 17_088;
/// The length of the stamp key: one SPX128f public key.
pub const BOARD_STAMP_KEY_BYTES: usize = 32;

/// The public identity of one board, as its stamp names it.
#[derive(Clone, Copy, Debug)]
pub struct BoardIdentity<'a> {
    /// The board's anchor id, a hash of its chip's identity.
    pub anchor_id: &'a [u8; 32],
    /// The board's partition key, which only the board's own firmware can derive.
    pub pk_host: &'a [u8],
    /// The chip's resident key.
    pub pk_chip: &'a [u8],
}

/// What the owner's stamp signs for `board`: `H(BOARD_STAMP_V1 ‖ anchor_id ‖ commit(pk_host) ‖
/// commit(pk_chip))`. Each key enters as its fixed-width commitment, as the anchor bundle binds it.
pub fn board_stamp_message(board: BoardIdentity<'_>) -> [u8; 32] {
    h(
        BOARD_STAMP_V1,
        &[
            board.anchor_id,
            &commit(board.pk_host),
            &commit(board.pk_chip),
        ],
    )
}

/// Why a board's stamp was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StampRefusal {
    /// The board came with no stamp.
    Missing,
    /// What came is not the length of a stamp.
    Length,
    /// The stamp does not verify under the stamp key over this board's identity: it was made by
    /// another key, or for another board.
    NotStamped,
}

impl StampRefusal {
    /// The refusal in words, as a receiver reports it.
    pub fn reason(self) -> &'static str {
        match self {
            StampRefusal::Missing => "the board carries no stamp",
            StampRefusal::Length => "the board's stamp is not the length of a stamp",
            StampRefusal::NotStamped => {
                "the board's stamp does not verify under the stamp key for this board's identity"
            }
        }
    }
}

/// One stamp key's public half.
pub type StampKey = [u8; BOARD_STAMP_KEY_BYTES];

/// The owner's stamp keys: the public half of each, compiled into the wallet and the board's signed
/// firmware. One now; a later key is added beside it, so a board stamped under this one stays
/// admitted. The key file is what `dsm-board-stamp genkey` wrote on the owner's computer.
pub const BOARD_STAMP_KEYS: &[StampKey] = &[*include_bytes!("../keys/board-stamp-key.pk32")];

/// `stamp` is the stamp of `board` under one of `stamp_keys`: a signature in the host-key scheme `S`
/// over [`board_stamp_message`]. With no key, no board is stamped. A later stamp key is added beside the
/// first, so boards stamped under the first stay admitted. Nothing else about the board is checked
/// here; the anchor bundle binds the same keys to the board's holder.
pub fn verify_board_stamp<S: HostSig>(
    stamp_keys: &[StampKey],
    board: BoardIdentity<'_>,
    stamp: &[u8],
) -> Result<(), StampRefusal> {
    if stamp.is_empty() {
        return Err(StampRefusal::Missing);
    }
    if stamp.len() != BOARD_STAMP_BYTES {
        return Err(StampRefusal::Length);
    }
    let message = board_stamp_message(board);
    if stamp_keys.iter().any(|key| S::verify(key, &message, stamp)) {
        Ok(())
    } else {
        Err(StampRefusal::NotStamped)
    }
}

/// The stamp key the crate's own tests stamp boards with, from a fixed seed: the owner's key never
/// leaves his computer, so a test's boards check stamps under this one.
#[cfg(test)]
pub(crate) mod test_keys {
    use super::StampKey;
    use std::sync::OnceLock;

    fn pair() -> &'static dsm_sphincs::SphincsKeyPair {
        static PAIR: OnceLock<dsm_sphincs::SphincsKeyPair> = OnceLock::new();
        PAIR.get_or_init(|| {
            match dsm_sphincs::generate_keypair_from_seed(
                dsm_sphincs::SphincsVariant::SPX128f,
                &[0x5A; 32],
            ) {
                Ok(pair) => pair,
                Err(e) => panic!("the test stamp key: {e:?}"),
            }
        })
    }

    /// The stamp keys a test board checks under: the test key alone.
    pub(crate) fn keys() -> &'static [StampKey] {
        static KEYS: OnceLock<[StampKey; 1]> = OnceLock::new();
        KEYS.get_or_init(|| [core::array::from_fn(|i| pair().public_key[i])])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BLAKE3-SPHINCS+ SPX128f, the scheme a stamp is in.
    struct Spx128f;
    impl HostSig for Spx128f {
        fn verify(pk: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
            matches!(
                dsm_sphincs::verify(dsm_sphincs::SphincsVariant::SPX128f, pk, message, sig),
                Ok(valid) if valid
            )
        }
    }

    type Run = Result<(), dsm_sphincs::Error>;

    fn stamp_key(seed: u8) -> Result<dsm_sphincs::SphincsKeyPair, dsm_sphincs::Error> {
        dsm_sphincs::generate_keypair_from_seed(dsm_sphincs::SphincsVariant::SPX128f, &[seed; 32])
    }

    /// The key list a verifier holds, of `keys`.
    fn keys(keys: &[&dsm_sphincs::SphincsKeyPair]) -> Vec<StampKey> {
        keys.iter()
            .map(|k| core::array::from_fn(|i| k.public_key[i]))
            .collect()
    }

    fn stamp_of(
        key: &dsm_sphincs::SphincsKeyPair,
        board: BoardIdentity<'_>,
    ) -> Result<Vec<u8>, dsm_sphincs::Error> {
        dsm_sphincs::sign(
            dsm_sphincs::SphincsVariant::SPX128f,
            &key.secret_key,
            &board_stamp_message(board),
        )
    }

    const ANCHOR: [u8; 32] = [0x11; 32];
    const PK_HOST: [u8; 32] = [0x22; 32];
    const PK_CHIP: [u8; 32] = [0x33; 32];

    fn board() -> BoardIdentity<'static> {
        BoardIdentity {
            anchor_id: &ANCHOR,
            pk_host: &PK_HOST,
            pk_chip: &PK_CHIP,
        }
    }

    #[test]
    fn the_sizes_are_the_schemes() {
        assert_eq!(
            BOARD_STAMP_BYTES,
            dsm_sphincs::signature_bytes(dsm_sphincs::SphincsVariant::SPX128f)
        );
        assert_eq!(
            BOARD_STAMP_KEY_BYTES,
            dsm_sphincs::public_key_bytes(dsm_sphincs::SphincsVariant::SPX128f)
        );
    }

    #[test]
    fn a_board_stamped_by_the_key_verifies() -> Run {
        let key = stamp_key(7)?;
        let stamp = stamp_of(&key, board())?;
        assert_eq!(
            verify_board_stamp::<Spx128f>(&keys(&[&key]), board(), &stamp),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn a_stamp_is_refused_for_any_other_board_or_key() -> Run {
        let key = stamp_key(7)?;
        let stamp = stamp_of(&key, board())?;
        let other = [0x44; 32];
        for (name, b) in [
            (
                "another anchor id",
                BoardIdentity {
                    anchor_id: &other,
                    ..board()
                },
            ),
            (
                "another pk_host",
                BoardIdentity {
                    pk_host: &other,
                    ..board()
                },
            ),
            (
                "another pk_chip",
                BoardIdentity {
                    pk_chip: &other,
                    ..board()
                },
            ),
        ] {
            assert_eq!(
                verify_board_stamp::<Spx128f>(&keys(&[&key]), b, &stamp),
                Err(StampRefusal::NotStamped),
                "{name}"
            );
        }
        let stranger = stamp_key(8)?;
        assert_eq!(
            verify_board_stamp::<Spx128f>(&keys(&[&stranger]), board(), &stamp),
            Err(StampRefusal::NotStamped),
            "another stamp key"
        );
        let by_stranger = stamp_of(&stranger, board())?;
        assert_eq!(
            verify_board_stamp::<Spx128f>(&keys(&[&key]), board(), &by_stranger),
            Err(StampRefusal::NotStamped),
            "a stamp made by another key"
        );
        Ok(())
    }

    #[test]
    fn a_missing_or_cut_stamp_is_refused_by_name() -> Run {
        let key = stamp_key(7)?;
        let stamp = stamp_of(&key, board())?;
        assert_eq!(
            verify_board_stamp::<Spx128f>(&keys(&[&key]), board(), &[]),
            Err(StampRefusal::Missing)
        );
        assert_eq!(
            verify_board_stamp::<Spx128f>(&keys(&[&key]), board(), &stamp[1..]),
            Err(StampRefusal::Length)
        );
        let mut flipped = stamp.clone();
        flipped[BOARD_STAMP_BYTES / 2] ^= 1;
        assert_eq!(
            verify_board_stamp::<Spx128f>(&keys(&[&key]), board(), &flipped),
            Err(StampRefusal::NotStamped)
        );
        Ok(())
    }

    /// A board stamped under either of two keys verifies under the pair, and no board verifies under
    /// no key.
    #[test]
    fn a_stamp_verifies_under_any_key_of_the_list_and_none_under_an_empty_one() -> Run {
        let first = stamp_key(7)?;
        let second = stamp_key(9)?;
        let by_second = stamp_of(&second, board())?;
        assert_eq!(
            verify_board_stamp::<Spx128f>(&keys(&[&first, &second]), board(), &by_second),
            Ok(())
        );
        assert_eq!(
            verify_board_stamp::<Spx128f>(&[], board(), &by_second),
            Err(StampRefusal::NotStamped)
        );
        Ok(())
    }

    #[test]
    fn the_message_separates_the_keys() {
        // pk_host and pk_chip enter as their own commitments, so swapping them names another board.
        let swapped = BoardIdentity {
            anchor_id: &ANCHOR,
            pk_host: &PK_CHIP,
            pk_chip: &PK_HOST,
        };
        assert_ne!(board_stamp_message(board()), board_stamp_message(swapped));
    }
}
