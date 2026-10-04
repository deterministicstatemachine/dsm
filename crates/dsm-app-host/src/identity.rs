// SPDX-License-Identifier: MIT OR Apache-2.0

//! This account's SDK and identity: the startup sequence a phone runs, then
//! a mnemonic-rooted genesis the first time.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use dsm_sdk::generated as pb;
use prost::Message;

use crate::Args;

/// This account, as the host names it.
#[derive(Clone)]
pub struct Account {
    pub device_id: [u8; 32],
    pub device_b32: String,
}

fn startup(operation: pb::startup_request::Operation) -> Result<(), String> {
    let request = pb::StartupRequest {
        operation: Some(operation),
    };
    let answer = pb::StartupResponse::decode(
        dsm_sdk::ingress::dispatch_startup_bytes(&request.encode_to_vec()).as_slice(),
    )
    .map_err(|e| format!("the startup answer: {e}"))?;
    match answer.result {
        Some(pb::startup_response::Result::OkBytes(..)) => Ok(()),
        Some(pb::startup_response::Result::Error(e)) => Err(e.message),
        None => Err("the startup answered nothing".into()),
    }
}

/// The startup a phone runs: the storage directory, the network's config,
/// then the SDK. An account created before comes back with its sealed seed.
pub fn start_sdk(args: &Args) -> Result<(), String> {
    let store = args.data_dir.join("sdk");
    std::fs::create_dir_all(&store).map_err(|e| format!("{}: {e}", store.display()))?;
    startup(pb::startup_request::Operation::SetStorageBaseDir(
        pb::SetStorageBaseDirOp {
            path_utf8: store.display().to_string(),
        },
    ))?;
    startup(pb::startup_request::Operation::ConfigureEnv(
        pb::ConfigureEnvOp {
            config_path_utf8: args.env_config.display().to_string(),
        },
    ))?;
    startup(pb::startup_request::Operation::InitializeSdk(
        pb::InitializeSdkOp {},
    ))
}

fn query(method: &str, args: Vec<u8>) -> Result<Vec<u8>, String> {
    let request = pb::IngressRequest {
        operation: Some(pb::ingress_request::Operation::RouterQuery(
            pb::RouterQueryOp {
                method: method.to_string(),
                args,
            },
        )),
    };
    crate::dispatch::ok_bytes(dsm_sdk::ingress::dispatch_ingress(request))
        .map_err(|e| format!("{method}: {e}"))
}

fn account(device_id: &[u8]) -> Result<Account, String> {
    let device_id: [u8; 32] = device_id
        .try_into()
        .map_err(|e| format!("this account's device id: {e}"))?;
    Ok(Account {
        device_id,
        device_b32: dsm_sdk::util::text_id::encode_base32_crockford(&device_id),
    })
}

/// This account's identity: the one the store holds, or a new one rooted in
/// a fresh BIP39 mnemonic. The mnemonic is written once, readable by this
/// user alone, before the genesis it roots: it is how the account is
/// recovered, and it is the operator's to keep.
pub fn ensure_identity(args: &Args) -> Result<Account, String> {
    if let Some(device_id) = dsm_sdk::sdk::app_state::AppState::get_device_id() {
        return account(&device_id);
    }
    let words = pb::ArgPack::decode(query("system.generateMnemonic", Vec::new())?.as_slice())
        .map_err(|e| format!("system.generateMnemonic: {e}"))?
        .body;
    let mnemonic = String::from_utf8(words).map_err(|e| format!("the generated mnemonic: {e}"))?;
    let path = args.data_dir.join("RECOVERY_MNEMONIC");
    let mut file =
        std::fs::File::create_new(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(mnemonic.as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let created = query(
        "system.createGenesisV2",
        crate::dispatch::arg_pack(pb::WalletCreateGenesisV2Request { mnemonic }.encode_to_vec()),
    )?;
    let envelope = pb::Envelope::decode(
        created
            .strip_prefix(&[0x03])
            .ok_or_else(|| "system.createGenesisV2: the answer is not framed 0x03".to_string())?,
    )
    .map_err(|e| format!("system.createGenesisV2: {e}"))?;
    match envelope.payload {
        Some(pb::envelope::Payload::GenesisCreatedResponse(created)) => {
            log::info!(
                "[host] created this account; its recovery mnemonic is in {}",
                path.display()
            );
            account(&created.device_id)
        }
        other => Err(format!("system.createGenesisV2 answered {other:?}")),
    }
}
