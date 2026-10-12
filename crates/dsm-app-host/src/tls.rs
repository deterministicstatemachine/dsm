// SPDX-License-Identifier: MIT OR Apache-2.0

//! The relay's TLS identity: a self-signed certificate made once and kept in
//! the data directory. A wallet trusts it through the pin the connect code
//! names (the code the player scanned off this application's own screen), so
//! no certificate authority is involved.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub struct RelayTls {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    /// The pin every connect code names: the TLS certificate hash of the
    /// leaf's DER.
    pub pin: [u8; 32],
}

const CERT: &str = "relay-cert.der";
const KEY: &str = "relay-key.der";

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file =
        std::fs::File::create_new(path).map_err(|e| format!("{}: {e}", path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The relay's certificate and key: the ones kept in `data_dir`, or new ones
/// naming `names` (and `localhost`).
pub fn load_or_make(data_dir: &Path, names: &[String]) -> Result<RelayTls, String> {
    let (cert_path, key_path) = (data_dir.join(CERT), data_dir.join(KEY));
    let (cert_der, key_der) = match (std::fs::read(&cert_path), std::fs::read(&key_path)) {
        (Ok(cert), Ok(key)) => (cert, key),
        (Err(cert), Err(key))
            if cert.kind() == std::io::ErrorKind::NotFound
                && key.kind() == std::io::ErrorKind::NotFound =>
        {
            let mut subject_alt_names = names.to_vec();
            subject_alt_names.push("localhost".to_string());
            let made = rcgen::generate_simple_self_signed(subject_alt_names)
                .map_err(|e| format!("making the relay's certificate: {e}"))?;
            let cert = made.cert.der().to_vec();
            let key = made.signing_key.serialize_der();
            write_private(&cert_path, &cert)?;
            write_private(&key_path, &key)?;
            (cert, key)
        }
        (cert, key) => {
            return Err(format!(
                "the relay's TLS identity is half there: {} {:?}, {} {:?}; remove both to make a new one",
                cert_path.display(),
                cert.map(|c| c.len()),
                key_path.display(),
                key.map(|k| k.len())
            ))
        }
    };
    let pin = dsm_sdk::sdk::connect::signed::cert_pin(&cert_der);
    Ok(RelayTls {
        cert_der,
        key_der,
        pin,
    })
}
