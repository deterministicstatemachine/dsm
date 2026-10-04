// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM Connect over the real connection (DSM Amendment A11).
//!
//! Two `dsm-app-host` processes, the binary this crate builds: one is a game's
//! own DSM account, the other a player's wallet. Both run against the storage
//! node's own code on Postgres (the SDK suites' harness, shared by `#[path]`),
//! as the fleet runs it. The wallet reaches the game's relay over TLS bound to
//! the pin in the game's code. The test speaks to each process only through
//! its ingress, the boundary the game server and the phone's bridge use;
//! between the two, everything is carried by the wallet's own listener and
//! each side's inbox poller. Nothing here forwards, forges or replays a
//! message.

/// The SDK suites' node harness, whole: its API is theirs as much as this
/// test's, and this test uses part of it.
#[path = "../../../dsm_client/deterministic_state_machine/dsm_sdk/src/test_support/nodes.rs"]
pub mod nodes;

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use dsm_sdk::generated as pb;
use dsm_sdk::handlers::wallet_routes::format_base_units_for_display;
use pb::connect_app_request_intent_v1::Kind;
use pb::connect_reply_v1::Reply;
use pb::envelope::Payload;
use prost::Message;
use serial_test::serial;

/// How long one step may take before the test names the step that did not
/// happen.
const STEP: Duration = Duration::from_secs(240);

fn era() -> [u8; 32] {
    dsm_sdk::policy::builtin_policy_commit("ERA").expect("ERA's policy")
}

fn era_decimals() -> u32 {
    dsm::core::token::era_policy::era_policy()
        .expect("ERA's policy")
        .decimals
}

fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    probe.local_addr().expect("its address").port()
}

/// A fresh directory for one test's processes.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("dsm-app-host-real-{}-{name}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).expect("clear the last run");
    }
    std::fs::create_dir_all(&dir).expect("the test directory");
    dir
}

/// The env config a host reads to reach `fleet`: every member, its endpoint
/// and incarnation, and the set's CA beside it, as the bundled config names
/// the fleet's.
fn env_config(dir: &Path, fleet: &nodes::NodeSet) -> PathBuf {
    std::fs::write(dir.join("fleet-ca.pem"), fleet.ca_pem()).expect("the fleet's CA");
    // The config admits loopback endpoints exactly when the fleet serves at one.
    let loopback = fleet.endpoints().iter().any(|endpoint| {
        let url = reqwest::Url::parse(endpoint).expect("a node endpoint URL");
        url.host_str()
            .expect("a node endpoint names its host")
            .parse::<std::net::IpAddr>()
            .expect("a node endpoint is an IP address")
            .is_loopback()
    });
    let mut cfg = format!(
        "allow_localhost = {loopback}\n\
         bitcoin_network = \"signet\"\n\
         custom_ca_certs = [\"fleet-ca.pem\"]\n"
    );
    for (member_id, endpoint, incarnation) in fleet.members() {
        cfg.push_str(&format!(
            "\n[[nodes]]\nname = \"{member_id}\"\nendpoint = \"{endpoint}\"\n\
             register_incarnation = \"{}\"\n",
            dsm_sdk::util::text_id::encode_base32_crockford(&incarnation)
        ));
    }
    let path = dir.join("dsm_env_config.toml");
    std::fs::write(&path, cfg).expect("the env config");
    path
}

/// Whether a router method reads or writes: the ingress carries each as its
/// own operation.
enum Route {
    Query,
    Invoke,
}

/// One `dsm-app-host` process and its ingress.
struct Host {
    name: &'static str,
    args: Vec<String>,
    dir: PathBuf,
    starts: u32,
    ingress: String,
    child: Option<tokio::process::Child>,
    http: reqwest::Client,
}

impl Host {
    fn new(name: &'static str, root: &Path, config: &Path) -> Self {
        let (game, relay) = (free_port(), free_port());
        let args = vec![
            "--data-dir".to_string(),
            root.join(name).display().to_string(),
            "--env-config".to_string(),
            config.display().to_string(),
            "--game-bind".to_string(),
            format!("127.0.0.1:{game}"),
            "--relay-bind".to_string(),
            format!("127.0.0.1:{relay}"),
            "--relay-endpoint".to_string(),
            format!("https://127.0.0.1:{relay}"),
            "--relay-name".to_string(),
            "127.0.0.1".to_string(),
        ];
        Self {
            name,
            args,
            dir: root.to_path_buf(),
            starts: 0,
            ingress: format!("http://127.0.0.1:{game}"),
            child: None,
            http: reqwest::Client::new(),
        }
    }

    /// Start the process (again, on the same account, after `stop`) and wait
    /// until its ingress answers. Each start logs to a file of its own.
    async fn start(&mut self) {
        self.starts += 1;
        let path = self.dir.join(format!("{}-{}.log", self.name, self.starts));
        let log = std::fs::File::create(&path).expect("the process log");
        let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_dsm-app-host"))
            .args(&self.args)
            .env("RUST_LOG", "info")
            .stdout(log.try_clone().expect("the process log"))
            .stderr(log)
            .spawn()
            .expect("start dsm-app-host");
        self.child = Some(child);
        let probe = format!("{}/activity/0", self.ingress);
        let deadline = tokio::time::Instant::now() + STEP;
        loop {
            let child = self.child.as_mut().expect("the process just started");
            if let Some(status) = child.try_wait().expect("the process's state") {
                panic!("{} exited ({status}): see {}", self.name, path.display());
            }
            let why = match self.http.get(&probe).send().await {
                Ok(answer) if answer.status().is_success() => return,
                Ok(answer) => format!("its ingress answered {}", answer.status()),
                Err(e) => format!("its ingress: {e}"),
            };
            assert!(
                tokio::time::Instant::now() < deadline,
                "{} did not come up within {} s ({why}): see {}",
                self.name,
                STEP.as_secs(),
                path.display()
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Kill the process, as a phone kills an app: nothing is shut down for it.
    async fn stop(&mut self) {
        let mut child = self.child.take().expect("a running process");
        child.kill().await.expect("stop the process");
    }

    /// This account's device id, from its own record.
    async fn device_id(&self) -> [u8; 32] {
        let bytes = self
            .http
            .get(format!("{}/activity/0", self.ingress))
            .send()
            .await
            .expect("the activity record")
            .bytes()
            .await
            .expect("its bytes");
        let record = pb::AppHostActivityV1::decode(bytes.as_ref()).expect("an activity record");
        record
            .device_id
            .as_slice()
            .try_into()
            .expect("a 32-byte device id")
    }

    /// One router call through the ingress; the envelope's payload, or the
    /// refusal the SDK answered.
    async fn call(&self, route: Route, method: &str, body: Vec<u8>) -> Result<Payload, String> {
        let args = pb::ArgPack {
            schema_hash: None,
            codec: pb::Codec::Proto as i32,
            body,
        }
        .encode_to_vec();
        let operation = match route {
            Route::Query => pb::ingress_request::Operation::RouterQuery(pb::RouterQueryOp {
                method: method.to_string(),
                args,
            }),
            Route::Invoke => pb::ingress_request::Operation::RouterInvoke(pb::RouterInvokeOp {
                method: method.to_string(),
                args,
            }),
        };
        let request = pb::IngressRequest {
            operation: Some(operation),
        };
        let answer = self
            .http
            .post(format!("{}/ingress", self.ingress))
            .header("content-type", "application/x-protobuf")
            .body(request.encode_to_vec())
            .send()
            .await
            .map_err(|e| format!("{} {method}: the ingress: {e}", self.name))?;
        let status = answer.status();
        let bytes = answer
            .bytes()
            .await
            .map_err(|e| format!("{} {method}: the answer: {e}", self.name))?;
        if !status.is_success() {
            return Err(format!(
                "{} {method}: {status}: {}",
                self.name,
                String::from_utf8_lossy(&bytes)
            ));
        }
        let response = pb::IngressResponse::decode(bytes.as_ref())
            .map_err(|e| format!("{} {method}: the answer: {e}", self.name))?;
        match response.result {
            Some(pb::ingress_response::Result::OkBytes(framed)) => {
                let body = framed
                    .strip_prefix(&[0x03])
                    .ok_or_else(|| format!("{} {method}: an answer not framed 0x03", self.name))?;
                let envelope = pb::Envelope::decode(body)
                    .map_err(|e| format!("{} {method}: the envelope: {e}", self.name))?;
                match envelope.payload {
                    Some(Payload::Error(e)) => {
                        Err(format!("{} {method}: {}", self.name, e.message))
                    }
                    Some(payload) => Ok(payload),
                    None => Err(format!("{} {method}: an empty envelope", self.name)),
                }
            }
            Some(pb::ingress_response::Result::Error(e)) => {
                Err(format!("{} {method}: {}", self.name, e.message))
            }
            None => Err(format!(
                "{} {method}: the ingress answered nothing",
                self.name
            )),
        }
    }

    /// A DSM Connect call; the reply, or the refusal.
    async fn connect(&self, route: Route, method: &str, body: Vec<u8>) -> Result<Reply, String> {
        match self.call(route, method, body).await? {
            Payload::ConnectReply(pb::ConnectReplyV1 { reply: Some(reply) }) => Ok(reply),
            other => Err(format!("{} {method} answered {other:?}", self.name)),
        }
    }

    /// One faucet claim for this account.
    async fn claim_faucet(&self) {
        let request = pb::FaucetClaimRequest {
            device_id: self.device_id().await.to_vec(),
        };
        match self
            .call(Route::Invoke, "faucet.claim", request.encode_to_vec())
            .await
        {
            Ok(Payload::FaucetClaimResponse(r)) => assert!(r.success, "{}", r.message),
            other => panic!("{} faucet.claim answered {other:?}", self.name),
        }
    }

    /// What this account's `balance.list` reports it can spend of `ticker`:
    /// the view the wallet renders. Refused when it names no such token.
    async fn balance(&self, ticker: &str) -> Result<u64, String> {
        match self.call(Route::Query, "balance.list", Vec::new()).await? {
            Payload::BalancesListResponse(list) => list
                .balances
                .iter()
                .find(|b| b.token_id == ticker)
                .map(|b| b.available)
                .ok_or_else(|| format!("{} holds no {ticker}", self.name)),
            other => Err(format!("{} balance.list answered {other:?}", self.name)),
        }
    }

    async fn holds(&self, ticker: &str) -> u64 {
        self.balance(ticker).await.expect("the balance")
    }
}

impl Drop for Host {
    /// A test that fails part-way still stops its processes.
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            if let Err(e) = child.start_kill() {
                eprintln!("{}: stopping the process: {e}", self.name);
            }
        }
    }
}

/// Wait for `probe` to answer, or fail naming `what` and the last reason it
/// gave for not answering yet.
async fn until<T, F, Fut>(what: &str, mut probe: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let deadline = tokio::time::Instant::now() + STEP;
    loop {
        let why = match probe().await {
            Ok(value) => return value,
            Err(why) => why,
        };
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what}: not within {} s; last: {why}",
            STEP.as_secs()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// What a token's policy lets its holders do (SoFi §49, §54). A token is
/// created with exactly the rules named for it.
#[derive(PartialEq)]
enum Rule {
    /// Holders send it on: the game delivers what it issues.
    Moves,
    /// Holders may burn it.
    Burns,
}

/// `game` creates a token of 0 decimals; its policy commit.
async fn create_token(game: &Host, ticker: &str, supply: u128, rules: &[Rule]) -> [u8; 32] {
    let request = pb::TokenCreateRequest {
        ticker: ticker.to_string(),
        alias: format!("{ticker} token"),
        decimals: 0,
        genesis_supply_u128: supply.to_be_bytes().to_vec(),
        burn_enabled: rules.contains(&Rule::Burns),
        transferable: rules.contains(&Rule::Moves),
        threshold: 1,
        description: String::new(),
        icon_url: String::new(),
        allowlist_device_ids: Vec::new(),
    };
    match game
        .call(Route::Invoke, "token.create", request.encode_to_vec())
        .await
    {
        Ok(Payload::TokenCreateResponse(r)) => r
            .policy_anchor
            .as_slice()
            .try_into()
            .expect("a 32-byte anchor"),
        other => panic!("token.create {ticker} answered {other:?}"),
    }
}

/// The game's vault: WILD against ERA, both reserves from its account. Its id.
async fn create_vault(
    game: &Host,
    wild: &[u8; 32],
    wild_reserve: u64,
    era_reserve: u64,
) -> [u8; 32] {
    let wild_side = (*wild, format_base_units_for_display(wild_reserve, 0));
    let era_side = (
        era(),
        format_base_units_for_display(era_reserve, era_decimals()),
    );
    let (a, b) = if wild_side.0 < era_side.0 {
        (wild_side, era_side)
    } else {
        (era_side, wild_side)
    };
    let request = pb::SofiCreateVaultRequest {
        token_a_policy_commit: a.0.to_vec(),
        token_b_policy_commit: b.0.to_vec(),
        reserve_a_entered: a.1,
        reserve_b_entered: b.1,
        fee_bps: 30,
    };
    match game
        .call(Route::Invoke, "sofi.createVault", request.encode_to_vec())
        .await
    {
        Ok(Payload::SofiVaultCreatedResponse(v)) => v
            .vault_id
            .as_slice()
            .try_into()
            .expect("a 32-byte vault id"),
        other => panic!("sofi.createVault answered {other:?}"),
    }
}

/// An online transfer of `amount` (of a token of 0 decimals) from `from` to
/// `to`, the request the frontend builds. Tried again while the pair's last
/// transfer settles, which each side's inbox poller carries; the step ends
/// when the recipient holds it.
async fn send(from: &Host, to: &Host, ticker: &str, amount: u64) {
    let before = match to.balance(ticker).await {
        Ok(held) => held,
        Err(why) => panic!("{} cannot receive {ticker}: {why}", to.name),
    };
    let request = pb::OnlineTransferSmartRequest {
        recipient_device_id: to.device_id().await.to_vec(),
        amount: format_base_units_for_display(amount, 0),
        token_id: ticker.to_string(),
        memo: format!("{} to {}", from.name, to.name),
    }
    .encode_to_vec();
    until(&format!("{} sends {amount} {ticker}", from.name), || {
        let request = request.clone();
        async move {
            match from
                .call(Route::Invoke, "wallet.sendSmart", request)
                .await?
            {
                Payload::OnlineTransferResponse(r) if r.success => Ok(()),
                Payload::OnlineTransferResponse(r) => Err(r.message),
                other => Err(format!("wallet.sendSmart answered {other:?}")),
            }
        }
    })
    .await;
    until(
        &format!("{} receives {amount} {ticker}", to.name),
        || async move {
            let held = to.balance(ticker).await?;
            if held == before + amount {
                Ok(())
            } else {
                Err(format!("{} holds {held} {ticker}", to.name))
            }
        },
    )
    .await;
}

fn cap(token: &[u8; 32], per_request: u64, total: u64) -> pb::ConnectCapV1 {
    pb::ConnectCapV1 {
        policy_commit: token.to_vec(),
        per_request,
        total,
    }
}

/// What a game asks for: accept the objects it issues, take payment in its
/// coin, swap the coin against ERA spending ERA, see the coin.
fn game_scopes(wild: &[u8; 32]) -> Vec<pb::ConnectScopeV1> {
    vec![
        pb::ConnectScopeV1 {
            kind: pb::ConnectScopeKind::AcceptIssued as i32,
            ..Default::default()
        },
        pb::ConnectScopeV1 {
            kind: pb::ConnectScopeKind::Pay as i32,
            caps: vec![cap(wild, 10, 30)],
            ..Default::default()
        },
        pb::ConnectScopeV1 {
            kind: pb::ConnectScopeKind::Swap as i32,
            policy_commits: vec![wild.to_vec(), era().to_vec()],
            caps: vec![cap(&era(), 1_000, 2_000)],
        },
        pb::ConnectScopeV1 {
            kind: pb::ConnectScopeKind::Holdings as i32,
            policy_commits: vec![wild.to_vec()],
            ..Default::default()
        },
    ]
}

/// The game asks the wallet for `kind`; the request's sequence number.
async fn ask(game: &Host, session: &[u8; 32], kind: Kind) -> u64 {
    let intent = pb::ConnectAppRequestIntentV1 {
        session_id: session.to_vec(),
        kind: Some(kind),
    };
    match game
        .connect(Route::Invoke, "connect.app.request", intent.encode_to_vec())
        .await
    {
        Ok(Reply::Request(made)) => made.seq,
        other => panic!("connect.app.request answered {other:?}"),
    }
}

/// What the game's account has established about request `seq`.
async fn status(
    game: &Host,
    session: &[u8; 32],
    seq: u64,
) -> Result<pb::ConnectAppStatusV1, String> {
    let request = pb::ConnectRequestRefV1 {
        session_id: session.to_vec(),
        seq,
    };
    match game
        .connect(Route::Invoke, "connect.app.status", request.encode_to_vec())
        .await?
    {
        Reply::Status(s) => Ok(s),
        other => Err(format!("connect.app.status answered {other:?}")),
    }
}

/// Request `seq`'s status once the wallet has answered it and the answer has
/// reached the game's account over the relay.
async fn answered(game: &Host, session: &[u8; 32], seq: u64, what: &str) -> pb::ConnectAppStatusV1 {
    until(what, || async move {
        let s = status(game, session, seq).await?;
        if s.answered {
            Ok(s)
        } else {
            Err(format!("request {seq} is unanswered"))
        }
    })
    .await
}

/// Request `seq`'s status once the game's account holds `want` as its fact.
async fn established(
    game: &Host,
    session: &[u8; 32],
    seq: u64,
    want: pb::ConnectFact,
    what: &str,
) -> pb::ConnectAppStatusV1 {
    until(what, || async move {
        let s = status(game, session, seq).await?;
        if fact(&s) == want {
            Ok(s)
        } else {
            Err(format!(
                "request {seq}: {:?} ({:?}: {}; {})",
                fact(&s),
                outcome(&s),
                s.reason,
                s.fact_detail
            ))
        }
    })
    .await
}

fn outcome(s: &pb::ConnectAppStatusV1) -> pb::ConnectOutcome {
    pb::ConnectOutcome::try_from(s.outcome).expect("a known outcome")
}

fn fact(s: &pb::ConnectAppStatusV1) -> pb::ConnectFact {
    pb::ConnectFact::try_from(s.fact).expect("a known fact")
}

fn held(s: &pb::ConnectAppStatusV1) -> BTreeMap<Vec<u8>, u64> {
    s.holdings
        .iter()
        .map(|h| (h.policy_commit.clone(), h.amount))
        .collect()
}

/// The game makes an offer, the wallet reads its code and approves it, and the
/// game's account holds the session. The session id.
async fn connect(game: &Host, wallet: &Host, wild: &[u8; 32]) -> [u8; 32] {
    // The host names its own relay and pin in the offer, whatever the game
    // sends for them.
    let request = pb::ConnectAppOfferRequestV1 {
        display_name: "Wildstate".into(),
        endpoint: String::new(),
        cert_pin: Vec::new(),
        scopes: game_scopes(wild),
        token_anchors: vec![wild.to_vec()],
    };
    let offer = match game
        .connect(Route::Invoke, "connect.app.offer", request.encode_to_vec())
        .await
    {
        Ok(Reply::Offer(offer)) => offer,
        other => panic!("connect.app.offer answered {other:?}"),
    };
    // The wallet reads the code: it fetches the signed offer from the game's
    // relay over TLS bound to the code's pin, and names the coin it has never
    // held from the policy its anchor commits to.
    let read = pb::ConnectPreviewRequestV1 {
        code: offer.code.clone(),
    };
    let preview = match wallet
        .connect(Route::Query, "connect.preview", read.encode_to_vec())
        .await
    {
        Ok(Reply::Preview(preview)) => preview,
        other => panic!("connect.preview answered {other:?}"),
    };
    assert_eq!(preview.display_name, "Wildstate");
    assert_eq!(preview.app_device_id, game.device_id().await.to_vec());
    assert!(
        preview
            .scope_lines
            .iter()
            .any(|l| l.contains("10 WILD a time")),
        "{:?}",
        preview.scope_lines
    );
    let approve = pb::ConnectApproveRequestV1 {
        offer_digest: preview.offer_digest.clone(),
        granted: Vec::new(),
    };
    let session: [u8; 32] = match wallet
        .connect(Route::Invoke, "connect.approve", approve.encode_to_vec())
        .await
    {
        Ok(Reply::Session(view)) => view.session_id.as_slice().try_into().expect("a session id"),
        other => panic!("connect.approve answered {other:?}"),
    };
    // The wallet posted its accept to the game's relay; the game's account
    // verified it, added the wallet as a contact and holds the session.
    let wallet_id = wallet.device_id().await.to_vec();
    let found = until("the game's account holds the session", || async {
        match game
            .connect(Route::Query, "connect.app.sessions", Vec::new())
            .await?
        {
            Reply::Sessions(list) => list
                .sessions
                .into_iter()
                .find(|s| s.session_id == session.to_vec())
                .ok_or_else(|| "no session yet".to_string()),
            other => Err(format!("connect.app.sessions answered {other:?}")),
        }
    })
    .await;
    assert_eq!(found.peer_device_id, wallet_id, "the session's wallet");
    assert_eq!(
        found.offer_digest, offer.offer_digest,
        "the session's offer"
    );
    session
}

/// A game and a wallet, each its own process, connect over the game's relay,
/// and the game drives the wallet within its grant:
///
/// - an object the game issued is accepted under the grant, then delivered;
/// - a payment counts only once the transfer is accepted onto the game's own
///   relationship, and runs once with two syncs racing the listener for it;
/// - holdings are proven, verified by the game against the wallet's root;
/// - a swap is an ordinary SoFi trade through the game's vault;
/// - a request outside the grant waits for the player, who declines it;
/// - an object the game did not issue, asked for as if it had, is refused;
/// - the wallet killed and started again picks the connection up and runs
///   nothing twice;
/// - after a disconnect, nothing the game asks is carried out, and a request
///   that was waiting for the player can no longer be approved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_game_and_a_wallet_connect_over_the_real_relay() {
    let fleet = nodes::NodeSet::start().await;
    let root = scratch("connect");
    let config = env_config(&root, &fleet);
    let mut game = Host::new("game", &root, &config);
    let mut wallet = Host::new("wallet", &root, &config);
    game.start().await;
    wallet.start().await;
    game.claim_faucet().await;
    wallet.claim_faucet().await;

    let wild = create_token(&game, "WILD", 1_000_000, &[Rule::Moves, Rule::Burns]).await;
    let vault = create_vault(&game, &wild, 5_000, 5_000).await;
    let session = connect(&game, &wallet, &wild).await;

    // The coin: the game's account pays it like any transfer. The wallet
    // rooted WILD when it approved the offer naming it.
    send(&game, &wallet, "WILD", 20).await;

    // A creature: an object of supply one the game issues. The wallet roots
    // it under the grant (its policy names the game as creator), and only
    // then can it be delivered.
    let creature = create_token(&game, "EM0001", 1, &[Rule::Moves]).await;
    let accept = ask(
        &game,
        &session,
        Kind::AcceptIssued(pb::ConnectAcceptIssuedV1 {
            anchor: creature.to_vec(),
        }),
    )
    .await;
    let accepted = answered(&game, &session, accept, "the wallet accepts the creature").await;
    assert_eq!(
        outcome(&accepted),
        pb::ConnectOutcome::CarriedOut,
        "{}",
        accepted.reason
    );
    assert_eq!(
        fact(&accepted),
        pb::ConnectFact::None,
        "accepting establishes nothing the game may grant on"
    );
    send(&game, &wallet, "EM0001", 1).await;

    // A payment: counted only from the transfer the game's account accepted.
    // Two syncs on the wallet race its listener for it; it runs once.
    let pay = ask(
        &game,
        &session,
        Kind::Pay(pb::ConnectPayV1 {
            policy_commit: wild.to_vec(),
            amount: 3,
            memo: "a capsule".into(),
        }),
    )
    .await;
    let (first, second) = tokio::join!(
        wallet.connect(Route::Invoke, "connect.sync", Vec::new()),
        wallet.connect(Route::Invoke, "connect.sync", Vec::new()),
    );
    for synced in [first, second] {
        match synced {
            Ok(Reply::Sessions(..)) => {}
            other => panic!("connect.sync answered {other:?}"),
        }
    }
    let paid = established(
        &game,
        &session,
        pay,
        pb::ConnectFact::Paid,
        "the payment lands",
    )
    .await;
    assert_eq!(outcome(&paid), pb::ConnectOutcome::CarriedOut);
    assert_eq!(wallet.holds("WILD").await, 17, "the payment ran once");

    // Holdings: a proof the game's account verifies against the wallet's root.
    let both = vec![wild.to_vec(), creature.to_vec()];
    let holdings = ask(
        &game,
        &session,
        Kind::Holdings(pb::ConnectHoldingsV1 {
            policy_commits: both.clone(),
        }),
    )
    .await;
    let proven = established(
        &game,
        &session,
        holdings,
        pb::ConnectFact::Holdings,
        "the holdings are proven",
    )
    .await;
    assert_eq!(
        held(&proven),
        BTreeMap::from([(wild.to_vec(), 17), (creature.to_vec(), 1)])
    );

    // A swap: an ordinary SoFi trade through the game's vault, no tap.
    let era_before = wallet.holds("ERA").await;
    let swap = ask(
        &game,
        &session,
        Kind::Swap(pb::ConnectSwapV1 {
            token_in: era().to_vec(),
            token_out: wild.to_vec(),
            amount_in: 500,
            min_amount_out: 1,
        }),
    )
    .await;
    let swapped = answered(&game, &session, swap, "the swap runs").await;
    assert_eq!(
        outcome(&swapped),
        pb::ConnectOutcome::CarriedOut,
        "{}",
        swapped.reason
    );
    assert_eq!(wallet.holds("ERA").await, era_before - 500);
    assert!(
        wallet.holds("WILD").await > 17,
        "the trade gave the wallet WILD"
    );
    let game_ref = &game;
    until(
        "the trade shows through the game's own vault",
        || async move {
            match game_ref
                .call(
                    Route::Invoke,
                    "sofi.vaults",
                    pb::SofiVaultsRequest {}.encode_to_vec(),
                )
                .await?
            {
                Payload::SofiVaultsResponse(owned) => {
                    let ours = owned
                        .vaults
                        .iter()
                        .find(|v| v.vault_id == vault.to_vec())
                        .ok_or_else(|| "the game's vault is not listed".to_string())?;
                    if ours.generation >= 1 {
                        Ok(())
                    } else {
                        Err(format!("the vault is at generation {}", ours.generation))
                    }
                }
                other => Err(format!("sofi.vaults answered {other:?}")),
            }
        },
    )
    .await;

    // Outside the grant: ERA was never payable to the game. It waits for the
    // player, who declines it on the wallet.
    let era_held = wallet.holds("ERA").await;
    let outside = ask(
        &game,
        &session,
        Kind::Pay(pb::ConnectPayV1 {
            policy_commit: era().to_vec(),
            amount: 1,
            memo: String::new(),
        }),
    )
    .await;
    let waiting = answered(&game, &session, outside, "the request reaches the phone").await;
    assert_eq!(
        wallet.holds("ERA").await,
        era_held,
        "nothing is paid without the player"
    );
    assert_eq!(outcome(&waiting), pb::ConnectOutcome::AwaitingApproval);
    match wallet
        .connect(Route::Query, "connect.pending", Vec::new())
        .await
    {
        Ok(Reply::Pending(list)) => assert_eq!(
            list.pending.iter().map(|p| p.seq).collect::<Vec<_>>(),
            vec![outside]
        ),
        other => panic!("connect.pending answered {other:?}"),
    }
    let decline = pb::ConnectRespondRequestV1 {
        session_id: session.to_vec(),
        seq: outside,
        decision: pb::ConnectDecision::Decline as i32,
    };
    match wallet
        .connect(Route::Invoke, "connect.respond", decline.encode_to_vec())
        .await
    {
        Ok(Reply::Decided(decided)) => assert_eq!(
            pb::ConnectOutcome::try_from(decided.outcome),
            Ok(pb::ConnectOutcome::Declined),
            "{}",
            decided.line
        ),
        other => panic!("connect.respond answered {other:?}"),
    }
    until("the decline reaches the game", || async move {
        let s = status(game_ref, &session, outside).await?;
        match outcome(&s) {
            pb::ConnectOutcome::Declined => Ok(()),
            other => Err(format!("request {outside} is {other:?}")),
        }
    })
    .await;
    assert_eq!(wallet.holds("ERA").await, era_held, "nothing was paid");

    // An object the game did not issue, asked for as if it had: the wallet
    // reads its committed policy and finds another creator.
    let foreign = create_token(&wallet, "OTHER", 5, &[Rule::Moves]).await;
    let posing = ask(
        &game,
        &session,
        Kind::AcceptIssued(pb::ConnectAcceptIssuedV1 {
            anchor: foreign.to_vec(),
        }),
    )
    .await;
    let refused = answered(&game, &session, posing, "the wallet refuses the object").await;
    assert_eq!(
        outcome(&refused),
        pb::ConnectOutcome::Failed,
        "{}",
        refused.reason
    );
    assert!(
        refused.reason.contains("names another creator"),
        "{}",
        refused.reason
    );

    // The wallet killed and started again: it picks the connection up where
    // it stood. Nothing it carried out runs again.
    let wild_held = wallet.holds("WILD").await;
    wallet.stop().await;
    wallet.start().await;
    let again = ask(
        &game,
        &session,
        Kind::Holdings(pb::ConnectHoldingsV1 {
            policy_commits: both,
        }),
    )
    .await;
    let proven_again = established(
        &game,
        &session,
        again,
        pb::ConnectFact::Holdings,
        "the restarted wallet proves its holdings",
    )
    .await;
    assert_eq!(
        held(&proven_again),
        BTreeMap::from([(wild.to_vec(), wild_held), (creature.to_vec(), 1)])
    );
    assert_eq!(
        wallet.holds("WILD").await,
        wild_held,
        "no payment ran again"
    );

    // A request outside the grant, waiting for the player when the wallet
    // disconnects.
    let waiting_then = ask(
        &game,
        &session,
        Kind::Pay(pb::ConnectPayV1 {
            policy_commit: era().to_vec(),
            amount: 1,
            memo: String::new(),
        }),
    )
    .await;
    let parked = answered(
        &game,
        &session,
        waiting_then,
        "the request reaches the phone",
    )
    .await;
    assert_eq!(outcome(&parked), pb::ConnectOutcome::AwaitingApproval);

    // Disconnected: a payment inside the old grant is never carried out, and
    // the waiting request went with the grant.
    let end = pb::ConnectSessionRefV1 {
        session_id: session.to_vec(),
    };
    match wallet
        .connect(Route::Invoke, "connect.disconnect", end.encode_to_vec())
        .await
    {
        Ok(Reply::Session(view)) => assert_eq!(
            pb::ConnectSessionStatus::try_from(view.status),
            Ok(pb::ConnectSessionStatus::Disconnected)
        ),
        other => panic!("connect.disconnect answered {other:?}"),
    }
    let after = ask(
        &game,
        &session,
        Kind::Pay(pb::ConnectPayV1 {
            policy_commit: wild.to_vec(),
            amount: 3,
            memo: String::new(),
        }),
    )
    .await;
    // A sync on the wallet carries nothing out: it reaches no session, and
    // the listener has stopped. Then the waiting request, approved, pays
    // nothing.
    let synced = wallet
        .connect(Route::Invoke, "connect.sync", Vec::new())
        .await;
    assert_eq!(wallet.holds("WILD").await, wild_held, "nothing was paid");
    let unanswered = status(&game, &session, after).await.expect("the status");
    assert!(!unanswered.answered, "a disconnected wallet answered");
    match synced {
        Ok(Reply::Sessions(list)) => assert!(list.sessions.is_empty(), "{:?}", list.sessions),
        other => panic!("connect.sync answered {other:?}"),
    }
    let era_held = wallet.holds("ERA").await;
    let approve = pb::ConnectRespondRequestV1 {
        session_id: session.to_vec(),
        seq: waiting_then,
        decision: pb::ConnectDecision::Approve as i32,
    };
    let approved = wallet
        .connect(Route::Invoke, "connect.respond", approve.encode_to_vec())
        .await;
    assert_eq!(wallet.holds("ERA").await, era_held, "nothing was paid");
    match approved {
        Err(why) => assert!(why.contains("no such connected application"), "{why}"),
        Ok(reply) => panic!("a disconnected grant approved a request: {reply:?}"),
    }
    match wallet
        .connect(Route::Query, "connect.pending", Vec::new())
        .await
    {
        Ok(Reply::Pending(list)) => assert!(list.pending.is_empty(), "{:?}", list.pending),
        other => panic!("connect.pending answered {other:?}"),
    }

    game.stop().await;
    wallet.stop().await;
    std::fs::remove_dir_all(&root).expect("remove the test's directory");
}
