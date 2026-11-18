// SPDX-License-Identifier: MIT OR Apache-2.0
//! The owner's board stamp (DSM Amendment A38, owner, 2026-11-18).
//!
//! Every board is set up by the owner before it ships, and he signs each board's public identity —
//! its `anchor_id`, `pk_host` and `pk_chip` — with his stamp key. Receivers admit only a board whose
//! stamp verifies under the stamp key compiled into the wallet and the board's firmware.
//!
//! ```text
//! dsm-board-stamp genkey  [--key FILE] [--public-key FILE]
//! dsm-board-stamp stamp   --identity FILE --out FILE [--key FILE]
//! dsm-board-stamp verify  --identity FILE --stamp FILE [--public-key FILE]
//! ```
//!
//! `genkey` makes the stamp key once: an SPX128f key from the operating system's randomness. The
//! secret key is kept only encrypted under the owner's passphrase (Argon2id, then ChaCha20-Poly1305
//! over the key with the file's header and the public key bound in), by default at
//! `~/.dsm-board-stamp/stamp-key.enc`: never in git, never on a phone or a board. The passphrase is
//! at least 16 characters, asked twice on the terminal, or given in `DSM_STAMPKEY_PASSIN`. The public
//! key is written to `crates/dsm-anchor-core/keys/board-stamp-key.pk32`, which the wallet and the
//! board's firmware compile in. Neither file is ever overwritten.
//!
//! `stamp` signs one board's identity and writes its stamp; `verify` checks a stamp under the public
//! key. The identity is the 96-byte file the bench tool writes from the board's own answer
//! (`used-chip-bench --board-identity FILE`: anchor id, `pk_host`, `pk_chip`), and the bench tool hands
//! the stamp to the board (`--keep-stamp FILE`). Nothing here talks to a board.

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anchor_core::stamp::{
    board_stamp_message, verify_board_stamp, BoardIdentity, StampKey, BOARD_STAMP_BYTES,
    BOARD_STAMP_KEY_BYTES,
};
use anchor_core::tropic::HostSig;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use dsm_sphincs::SphincsVariant;
use zeroize::Zeroizing;

/// The stamp's scheme: BLAKE3-SPHINCS+ SPX128f, the scheme of the `pk_host` it vouches for.
const SCHEME: SphincsVariant = SphincsVariant::SPX128f;
/// The first bytes of a stamp-key file, naming its layout.
const MAGIC: &[u8; 8] = b"DSMSTK01";
/// Argon2id's cost: 64 MiB, three passes, one lane.
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_PASSES: u32 = 3;
const ARGON2_LANES: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
/// The seed the stamp key is generated from.
const SEED_LEN: usize = 32;
/// An SPX128f secret key: `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`.
const SECRET_KEY_LEN: usize = 64;
const TAG_LEN: usize = 16;
/// Magic, the three Argon2id costs, salt, nonce and public key: the part of the file bound as the
/// cipher's associated data.
const HEADER_LEN: usize = MAGIC.len() + 12 + SALT_LEN + NONCE_LEN + BOARD_STAMP_KEY_BYTES;
const KEY_FILE_LEN: usize = HEADER_LEN + SECRET_KEY_LEN + TAG_LEN;
/// The shortest passphrase the key is kept under.
const MIN_PASSPHRASE: usize = 16;
/// Where the passphrase can be given instead of typed.
const PASSPHRASE_ENV: &str = "DSM_STAMPKEY_PASSIN";

/// BLAKE3-SPHINCS+ SPX128f verification.
struct Spx128f;
impl HostSig for Spx128f {
    fn verify(pk: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
        matches!(dsm_sphincs::verify(SCHEME, pk, message, sig), Ok(valid) if valid)
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("dsm-board-stamp: {why}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let (command, rest) = args.split_first().ok_or_else(|| usage("name a command"))?;
    let flags = Flags::parse(rest)?;
    match command.as_str() {
        "genkey" => genkey(&flags.key_path()?, &flags.public_key_path()),
        "stamp" => stamp(&flags),
        "verify" => verify(&flags),
        other => Err(usage(&format!("unknown command {other:?}"))),
    }
}

fn usage(why: &str) -> String {
    format!(
        "{why}\nusage:\n  dsm-board-stamp genkey [--key FILE] [--public-key FILE]\n  \
         dsm-board-stamp stamp --identity FILE --out FILE [--key FILE]\n  \
         dsm-board-stamp verify --identity FILE --stamp FILE [--public-key FILE]"
    )
}

/// The command line's `--name value` pairs.
struct Flags(Vec<(String, String)>);

impl Flags {
    fn parse(rest: &[String]) -> Result<Self, String> {
        let mut pairs = Vec::new();
        let mut it = rest.iter();
        while let Some(name) = it.next() {
            let Some(flag) = name.strip_prefix("--") else {
                return Err(usage(&format!("{name:?} is not a --flag")));
            };
            let value = it
                .next()
                .ok_or_else(|| usage(&format!("--{flag} needs a value")))?;
            if pairs
                .iter()
                .any(|(seen, _): &(String, String)| seen == flag)
            {
                return Err(usage(&format!("--{flag} is given twice")));
            }
            pairs.push((flag.to_string(), value.clone()));
        }
        Ok(Self(pairs))
    }

    fn get(&self, flag: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(name, _)| name == flag)
            .map(|(_, value)| value.as_str())
    }

    fn need(&self, flag: &str) -> Result<&str, String> {
        self.get(flag)
            .ok_or_else(|| usage(&format!("--{flag} is needed")))
    }

    fn key_path(&self) -> Result<PathBuf, String> {
        match self.get("key") {
            Some(path) => Ok(PathBuf::from(path)),
            None => {
                let home = std::env::var("HOME")
                    .map_err(|e| format!("no --key given and HOME is not set: {e}"))?;
                Ok(Path::new(&home).join(".dsm-board-stamp/stamp-key.enc"))
            }
        }
    }

    fn public_key_path(&self) -> PathBuf {
        match self.get("public-key") {
            Some(path) => PathBuf::from(path),
            None => Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../dsm-anchor-core/keys/board-stamp-key.pk32"),
        }
    }

    /// The board the `--identity` file names.
    fn board(&self) -> Result<OwnedBoard, String> {
        let path = self.need("identity")?;
        let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        OwnedBoard::from_identity(&bytes).map_err(|why| format!("{path}: {why}"))
    }
}

/// One board's identity, as the bench tool writes it from the board's own answer. An SPX128f
/// `pk_host` and the chip's Ed25519 `pk_chip` are each 32 bytes.
struct OwnedBoard {
    anchor_id: [u8; 32],
    pk_host: [u8; 32],
    pk_chip: [u8; 32],
}

impl OwnedBoard {
    /// The 96 bytes `used-chip-bench --board-identity` writes: anchor id, `pk_host`, `pk_chip`.
    fn from_identity(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 96 {
            return Err(format!("{} bytes, not a board identity's 96", bytes.len()));
        }
        let part = |at: usize| -> Result<[u8; 32], String> {
            <[u8; 32]>::try_from(&bytes[at..at + 32])
                .map_err(|e| format!("the identity's bytes at {at}: {e}"))
        };
        Ok(Self {
            anchor_id: part(0)?,
            pk_host: part(32)?,
            pk_chip: part(64)?,
        })
    }

    fn identity(&self) -> BoardIdentity<'_> {
        BoardIdentity {
            anchor_id: &self.anchor_id,
            pk_host: &self.pk_host,
            pk_chip: &self.pk_chip,
        }
    }
}

/// Make the stamp key, keep it under the owner's passphrase at `key_path`, and write its public key to
/// `public_path`.
fn genkey(key_path: &Path, public_path: &Path) -> Result<(), String> {
    for path in [key_path, public_path] {
        if path.exists() {
            return Err(format!(
                "{} already exists; a stamp key is made once and never replaced here",
                path.display()
            ));
        }
    }
    let passphrase = new_passphrase()?;

    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    getrandom::fill(&mut seed[..]).map_err(|e| format!("the system's randomness: {e}"))?;
    let pair = dsm_sphincs::generate_keypair_from_seed(SCHEME, &seed)
        .map_err(|e| format!("making the SPX128f key: {e:?}"))?;
    let public: [u8; BOARD_STAMP_KEY_BYTES] = pair
        .public_key
        .as_slice()
        .try_into()
        .map_err(|e| format!("the public key is {} bytes: {e}", pair.public_key.len()))?;
    if pair.secret_key.len() != SECRET_KEY_LEN {
        return Err(format!(
            "the secret key is not the {SECRET_KEY_LEN} bytes an SPX128f key is"
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|e| format!("the system's randomness: {e}"))?;
    getrandom::fill(&mut nonce).map_err(|e| format!("the system's randomness: {e}"))?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&ARGON2_MEMORY_KIB.to_le_bytes());
    header.extend_from_slice(&ARGON2_PASSES.to_le_bytes());
    header.extend_from_slice(&ARGON2_LANES.to_le_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&public);

    let cipher = cipher_for(
        &passphrase,
        &salt,
        ARGON2_MEMORY_KIB,
        ARGON2_PASSES,
        ARGON2_LANES,
    )?;
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &pair.secret_key,
                aad: &header,
            },
        )
        .map_err(|e| format!("sealing the secret key: {e}"))?;
    let mut file = header;
    file.extend_from_slice(&sealed);
    if file.len() != KEY_FILE_LEN {
        return Err(format!("the key file came to {} bytes", file.len()));
    }

    // Open the sealed key before keeping it: what is written must open under this passphrase.
    let (secret, opened_public) = open_key_bytes(&file, &passphrase)?;
    if opened_public != public || secret.as_slice() != pair.secret_key.as_slice() {
        return Err("the sealed key does not open to the key just made".to_string());
    }

    if let Some(dir) = key_path.parent() {
        if !dir.exists() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
    }
    if let Some(dir) = public_path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    write_new(key_path, &file, 0o600)?;
    write_new(public_path, &public, 0o644)?;
    println!(
        "stamp key kept, under your passphrase, at {}",
        key_path.display()
    );
    println!(
        "its public key ({} bytes) written to {}: the wallet and the board's firmware compile it in",
        public.len(),
        public_path.display()
    );
    Ok(())
}

/// Sign one board's identity with the stamp key and write its stamp.
fn stamp(flags: &Flags) -> Result<(), String> {
    let board = flags.board()?;
    let out = PathBuf::from(flags.need("out")?);
    if out.exists() {
        return Err(format!("{} already exists", out.display()));
    }
    let key_path = flags.key_path()?;
    let mut file = Vec::new();
    File::open(&key_path)
        .and_then(|mut f| f.read_to_end(&mut file))
        .map_err(|e| format!("{}: {e}", key_path.display()))?;
    let passphrase = ask("Stamp-key passphrase: ")?;
    let (secret, public) = open_key_bytes(&file, &passphrase)?;
    let message = board_stamp_message(board.identity());
    let signature = dsm_sphincs::sign(SCHEME, &secret, &message)
        .map_err(|e| format!("signing the board's identity: {e:?}"))?;
    verify_board_stamp::<Spx128f>(&[public], board.identity(), &signature)
        .map_err(|refusal| format!("the stamp just made does not verify: {}", refusal.reason()))?;
    write_new(&out, &signature, 0o644)?;
    println!(
        "the board's stamp ({} bytes) written to {}: have the board keep it with \
         `used-chip-bench --keep-stamp {}`",
        signature.len(),
        out.display(),
        out.display()
    );
    Ok(())
}

/// Check a stamp under the stamp key's public key.
fn verify(flags: &Flags) -> Result<(), String> {
    let board = flags.board()?;
    let stamp_path = PathBuf::from(flags.need("stamp")?);
    let public_path = flags.public_key_path();
    let public =
        std::fs::read(&public_path).map_err(|e| format!("{}: {e}", public_path.display()))?;
    let public = StampKey::try_from(public.as_slice()).map_err(|e| {
        format!(
            "{} is {} bytes, not a stamp key's {BOARD_STAMP_KEY_BYTES}: {e}",
            public_path.display(),
            public.len()
        )
    })?;
    let stamp = std::fs::read(&stamp_path).map_err(|e| format!("{}: {e}", stamp_path.display()))?;
    if stamp.len() != BOARD_STAMP_BYTES {
        return Err(format!(
            "{} is {} bytes, not a stamp's {BOARD_STAMP_BYTES}",
            stamp_path.display(),
            stamp.len()
        ));
    }
    verify_board_stamp::<Spx128f>(&[public], board.identity(), &stamp)
        .map_err(|refusal| refusal.reason().to_string())?;
    println!("the stamp verifies for the board this identity names");
    Ok(())
}

/// The cipher a key file is sealed with: ChaCha20-Poly1305 under Argon2id of the passphrase.
fn cipher_for(
    passphrase: &str,
    salt: &[u8],
    memory_kib: u32,
    passes: u32,
    lanes: u32,
) -> Result<ChaCha20Poly1305, String> {
    let params = argon2::Params::new(memory_kib, passes, lanes, Some(32))
        .map_err(|e| format!("the key file's Argon2id costs: {e}"))?;
    let kdf = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; SEED_LEN]);
    kdf.hash_password_into(passphrase.as_bytes(), salt, &mut key[..])
        .map_err(|e| format!("deriving the key from the passphrase: {e}"))?;
    Ok(ChaCha20Poly1305::new(Key::from_slice(&key[..])))
}

/// The secret key and public key a stamp-key file holds, opened with `passphrase`. A wrong passphrase,
/// a changed header or a changed public key does not open.
fn open_key_bytes(
    file: &[u8],
    passphrase: &str,
) -> Result<(Zeroizing<Vec<u8>>, [u8; BOARD_STAMP_KEY_BYTES]), String> {
    if file.len() != KEY_FILE_LEN {
        return Err(format!(
            "a stamp-key file is {KEY_FILE_LEN} bytes; this one is {}",
            file.len()
        ));
    }
    let (header, sealed) = file.split_at(HEADER_LEN);
    if &header[..MAGIC.len()] != MAGIC {
        return Err("not a stamp-key file".to_string());
    }
    let word = |at: usize| -> Result<u32, String> {
        header[at..at + 4]
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|e| format!("the key file's header: {e}"))
    };
    let costs_at = MAGIC.len();
    let salt_at = costs_at + 12;
    let nonce_at = salt_at + SALT_LEN;
    let public_at = nonce_at + NONCE_LEN;
    let cipher = cipher_for(
        passphrase,
        &header[salt_at..nonce_at],
        word(costs_at)?,
        word(costs_at + 4)?,
        word(costs_at + 8)?,
    )?;
    let secret = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&header[nonce_at..public_at]),
                Payload {
                    msg: sealed,
                    aad: header,
                },
            )
            .map_err(|e| {
                format!("the key does not open: a wrong passphrase, or a changed file ({e})")
            })?,
    );
    let public: [u8; BOARD_STAMP_KEY_BYTES] = header[public_at..]
        .try_into()
        .map_err(|e| format!("the key file's public key: {e}"))?;
    // An SPX128f secret key ends with its public key.
    if secret.len() != SECRET_KEY_LEN || secret[SECRET_KEY_LEN - BOARD_STAMP_KEY_BYTES..] != public
    {
        return Err("the secret key does not belong to the file's public key".to_string());
    }
    Ok((secret, public))
}

/// A new passphrase, asked twice, or taken from `DSM_STAMPKEY_PASSIN`.
fn new_passphrase() -> Result<Zeroizing<String>, String> {
    let first = ask("New stamp-key passphrase (16 or more characters): ")?;
    if first.chars().count() < MIN_PASSPHRASE {
        return Err(format!(
            "the passphrase must be at least {MIN_PASSPHRASE} characters"
        ));
    }
    if std::env::var_os(PASSPHRASE_ENV).is_none() {
        let again = ask("The same passphrase again: ")?;
        if again.as_str() != first.as_str() {
            return Err("the two passphrases differ".to_string());
        }
    }
    Ok(first)
}

/// The passphrase from `DSM_STAMPKEY_PASSIN`, or typed on the terminal with echo off.
fn ask(prompt: &str) -> Result<Zeroizing<String>, String> {
    if let Some(given) = std::env::var_os(PASSPHRASE_ENV) {
        return given
            .into_string()
            .map(Zeroizing::new)
            .map_err(|_given| format!("{PASSPHRASE_ENV} is not UTF-8"));
    }
    let tty = || File::open("/dev/tty").map_err(|e| format!("no terminal to ask on: {e}"));
    let stty = |setting: &str| -> Result<(), String> {
        let status = Command::new("stty")
            .arg(setting)
            .stdin(tty()?)
            .status()
            .map_err(|e| format!("stty {setting}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("stty {setting}: {status}"))
        }
    };
    eprint!("{prompt}");
    stty("-echo")?;
    let typed = read_line(tty()?);
    let echo_back = stty("echo");
    eprintln!();
    let line = typed?;
    echo_back?;
    String::from_utf8(line.to_vec())
        .map(Zeroizing::new)
        .map_err(|e| format!("the passphrase is not UTF-8: {e}"))
}

/// One line from `source`, without its line ending, read a byte at a time so no buffer keeps a copy.
fn read_line(mut source: File) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut line = Zeroizing::new(Vec::new());
    let mut byte = [0u8; 1];
    loop {
        let n = source
            .read(&mut byte)
            .map_err(|e| format!("reading the passphrase: {e}"))?;
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            line.push(byte[0]);
        }
    }
    Ok(line)
}

/// Write `bytes` to a new file at `path` with `mode`; an existing file is never replaced.
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut file = File::create_new(path).map_err(|e| format!("{}: {e}", path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key file made and opened the way `genkey` and `stamp` do, at test costs.
    fn sealed_file(
        passphrase: &str,
        seed: u8,
    ) -> Result<(Vec<u8>, dsm_sphincs::SphincsKeyPair), String> {
        let pair = dsm_sphincs::generate_keypair_from_seed(SCHEME, &[seed; SEED_LEN])
            .map_err(|e| format!("{e:?}"))?;
        let (memory, passes, lanes) = (64u32, 1u32, 1u32);
        // Drawn as `genkey` draws them.
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut salt).map_err(|e| format!("the system's randomness: {e}"))?;
        getrandom::fill(&mut nonce).map_err(|e| format!("the system's randomness: {e}"))?;
        let mut header = Vec::new();
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&memory.to_le_bytes());
        header.extend_from_slice(&passes.to_le_bytes());
        header.extend_from_slice(&lanes.to_le_bytes());
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);
        header.extend_from_slice(&pair.public_key);
        let sealed = cipher_for(passphrase, &salt, memory, passes, lanes)?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &pair.secret_key,
                    aad: &header,
                },
            )
            .map_err(|e| e.to_string())?;
        header.extend_from_slice(&sealed);
        Ok((header, pair))
    }

    #[test]
    fn a_key_file_opens_only_under_its_passphrase_and_unchanged() -> Result<(), String> {
        let (file, pair) = sealed_file("a passphrase of some length", 5)?;
        let (secret, public) = open_key_bytes(&file, "a passphrase of some length")?;
        assert_eq!(secret.as_slice(), pair.secret_key.as_slice());
        assert_eq!(public.as_slice(), pair.public_key.as_slice());

        assert!(
            matches!(open_key_bytes(&file, "another passphrase entirely"), Err(why) if why.contains("does not open"))
        );
        for at in [
            0,
            MAGIC.len() + 1,
            HEADER_LEN - 1,
            HEADER_LEN + 3,
            KEY_FILE_LEN - 1,
        ] {
            let mut changed = file.clone();
            changed[at] ^= 1;
            assert!(
                matches!(
                    open_key_bytes(&changed, "a passphrase of some length"),
                    Err(_why)
                ),
                "a file changed at byte {at} opened"
            );
        }
        assert!(matches!(
            open_key_bytes(&file[1..], "a passphrase of some length"),
            Err(_why)
        ));
        Ok(())
    }

    #[test]
    fn a_stamp_from_the_kept_key_verifies_for_its_board_alone() -> Result<(), String> {
        let (file, _pair) = sealed_file("a passphrase of some length", 6)?;
        let (secret, public) = open_key_bytes(&file, "a passphrase of some length")?;
        let board = OwnedBoard {
            anchor_id: [1; 32],
            pk_host: [2; 32],
            pk_chip: [3; 32],
        };
        let stamp = dsm_sphincs::sign(SCHEME, &secret, &board_stamp_message(board.identity()))
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            verify_board_stamp::<Spx128f>(&[public], board.identity(), &stamp),
            Ok(())
        );
        let other = OwnedBoard {
            anchor_id: [9; 32],
            ..board
        };
        assert!(matches!(
            verify_board_stamp::<Spx128f>(&[public], other.identity(), &stamp),
            Err(anchor_core::stamp::StampRefusal::NotStamped)
        ));
        Ok(())
    }

    #[test]
    fn an_identity_file_is_ninety_six_bytes_in_order() {
        let bytes: Vec<u8> = (0u8..96).collect();
        let board = match OwnedBoard::from_identity(&bytes) {
            Ok(board) => board,
            Err(why) => panic!("{why}"),
        };
        assert_eq!(board.anchor_id[0], 0);
        assert_eq!(board.pk_host[0], 32);
        assert_eq!(board.pk_chip[31], 95);
        assert!(matches!(
            OwnedBoard::from_identity(&bytes[1..]),
            Err(_short)
        ));
    }
}
