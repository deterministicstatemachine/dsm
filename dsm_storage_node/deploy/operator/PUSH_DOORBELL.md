# Inbox doorbell: the storage nodes push the phone

An open wallet waits on its spools with long-polls (`POST /api/v2/b0x/wait`).
Off screen, it holds no connection: each storage node keeps a **doorbell** for
it and sends one empty push when an entry lands on one of its spools: Firebase
Cloud Messaging (FCM) for an Android phone, the Apple Push Notification service
(APNs) for an iPhone. The push wakes the app, which runs the same sync a wait's
answer runs. What landed is read and verified exactly as before. Nothing in
acceptance or verification changed.

## What a push carries

Every FCM push the node sends is the same message, apart from the token it goes
to:

```json
{"message": {"token": "<the phone's FCM token>",
             "data": {"dsm": "inbox"},
             "android": {"priority": "HIGH", "collapse_key": "dsm-inbox"}}}
```

It holds no amount, sender, address, spool or count. The one data entry is the
same constant in every push. It is there because Firebase documents delivery to
the app's `onMessageReceived` only for data messages, and a message with no data
at all is not a documented case. `HIGH` priority wakes a phone in Doze.
`collapse_key` folds several waiting wakes into one.

Every APNs push is the same background push, apart from the device it goes to:
`POST /3/device/<device token, hex>` over HTTP/2 with `apns-push-type:
background`, `apns-priority: 5`, `apns-topic: <bundle id>`, `apns-collapse-id:
dsm-inbox`, and the body `{"aps":{"content-available":1}}`. A background push
needs no permission from the user and shows nothing on screen. Apple requires
priority 5 for it, and may hold or drop background pushes to a phone it judges
busy (low power, many recent pushes): the wake is best-effort, and the app
reads its inbox whenever it is opened.

## Who may change a doorbell, and why no write grant guards it

A doorbell (`B0xDoorbell`: key, push token, spools) is named on the node by
`BLAKE3("DSM/b0x-doorbell/v1", key)`. The device derives a different key for
each node: keyed BLAKE3 of the node's endpoint under its master seed
(`DSM/b0x-doorbell-key/v1`). Registering under a key replaces that key's
doorbell, and removing takes it down. Nothing else touches it. So no device
can replace or remove another device's token. Another registration on the same
spool is a separate doorbell that stands beside the first. A node never holds
a key that works on another node.

Doorbells are not guarded by an A34-style write grant, for these reasons:

- A grant guards what a spool holds, and readers verify that. A doorbell holds
  nothing anyone reads. It only says where an empty push goes.
- A stranger's doorbell on someone's spool would only tell them when an entry
  lands. The only parties who know a spool's address are the relationship's
  writer and the nodes holding the spool, and they already see every entry
  land.
- A grant could not work anyway. A relationship's first inbox is bound to its
  writer's lock (A37), so the reader holds no key for it.
- A SPHINCS+ signature per registration would add about 50 KB per node every
  time the routes move.

## Bounds

Doorbells are kept in the node's memory, never in Postgres. The node schema is
unchanged (still 4), so the fleet upgrades in place.

- A node keeps at most 32,768 doorbells, watching 262,144 spools in all.
- One peer (an IPv4 address or IPv6 /64, as the node's listener counts peers)
  can register at most 256 doorbells. Registering past that takes down that
  peer's own oldest doorbell, never another peer's.
- A registration past the node's bounds gets `503`, and that device keeps its
  waits. A flood of registrations takes no standing doorbell down.
- One spool takes at most 8 doorbells, and an arrival rings every one of them. A ninth
  registration on the spool is refused, so no registration displaces a doorbell that stands.
- Pushes are sent one at a time from a queue of 4,096. A doorbell already
  queued is not queued again.
- A token that FCM answers `404` for (the app was uninstalled) takes its
  doorbell down.

A node restart forgets its doorbells. A device puts them back:

- whenever its routes or its token change;
- on every push;
- every time the app goes off screen;
- whenever one of its waits at a node fails, which is how a node that
  restarted while the app was on screen is noticed.

A node that restarts while the phone sleeps and receives nothing rings no one
until the app is next opened or rung by another node. At least N − K + 1 nodes
must ring for the doorbells to count as covering the fleet.

## The device

- **SDK** (`sdk/inbox_doorbell.rs`). Every time the waiter plans
  (`inbox_waiter::plan`), the device's doorbell is put up at each member for
  exactly the routes the plan covers. A member is re-posted only where the
  routes or the token changed, unless a refresh was asked for. While the app is
  off screen and the doorbells stand on N − K + 1 members, the waiter holds no
  wait and the poller keeps no timer for arrivals. On screen, the waits stay
  exactly as before.
- **Lifecycle**: `onAppBackgrounded` answers `Backgrounded::Ringing`
  (host may stop the foreground service) when the doorbells cover the fleet.
  Otherwise it answers `Listening` (foreground service stays), as before.
- **Android**:
  - `InboxPush` hands the FCM token to Rust. With no Google Play services, or a
    build with no `google-services.json`, it calls `pushUnavailable(reason)`,
    logs the reason, and the app keeps its waits, its foreground service and
    the battery exemption.
  - `InboxPushService` takes every push as a wake through JNI
    `onPushWake()`. If Android started the process for the push,
    `HeadlessWallet` first runs the same Rust startup MainActivity runs, with
    no screen. The wallet seed is unsealed from the hardware vault, as on any
    cold start.
  - The battery exemption is asked for only on a phone with no push.
- **iOS (APNs)**:
  - `AppDelegate` registers for remote notifications and hands the device
    token's bytes to Rust (`dsm_ffi_set_apns_device_token`). The doorbell
    carries them as Base32 Crockford with `service = PUSH_SERVICE_APNS`; the
    node renders Apple's hex form only in the path it calls.
  - A failed registration calls `dsm_ffi_push_unavailable`, logs the reason,
    and the app keeps its waits while open.
  - A push calls `dsm_ffi_on_push_wake(25000)`, which runs the sync and waits
    for it, because iOS suspends the app once the push is answered. When iOS
    launched the app for the push, `HeadlessWallet` first runs the same Rust
    startup the wallet screen runs, with no screen.
  - The app declares `UIBackgroundModes: remote-notification` and the
    `aps-environment` entitlement (`DsmWallet/DsmWallet.entitlements`).

## How the node authenticates to Google, with no signing in the node

FCM's HTTP v1 API takes an OAuth access token. The usual way to get one is to
sign a JWT with a service-account key, which reads the clock. The node does
neither: `tests/no_protocol_signing.rs` and `tests/no_clock_reads.rs` stand
unchanged. Instead it uses Google's **Workload Identity Federation with X.509
certificates**:

1. `POST https://sts.mtls.googleapis.com/v1/token` over mutual TLS with the
   node's client certificate. The certificate chain is the subject token. The
   answer is a federated access token.
2. `POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<sa>:generateAccessToken`
   with it. The answer is the service account's access token.
3. `POST https://fcm.googleapis.com/v1/projects/<project>/messages:send` with
   that token.

The certificate's private key is a **transport key**. TLS uses it exactly as
it uses the node's server key, under the 2026-10-28 decision "Transport keys
permitted, protocol-signing keys prohibited". The node's own code signs
nothing. An access token is kept until Google answers `401`, then made again
once for that push. No expiry is read or timed. Google's JSON is used at this
boundary only.

## What the owner supplies

Nothing here is committed. Every value is yours.

### 1. Firebase project, for the app

1. In the Firebase console, create a project, or use an existing Google Cloud
   project.
2. Add an Android app with package name `com.dsm.wallet`.
3. Download **`google-services.json`** to
   **`dsm_client/android/app/google-services.json`** (git-ignored). The build
   applies the Google Services plugin only when this file is there. A build
   without it has no push, logs that at configuration, and keeps the
   foreground service.

### 2. Google Cloud, for the nodes (same project)

```bash
PROJECT_ID=<project id>
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
gcloud services enable fcm.googleapis.com iamcredentials.googleapis.com sts.googleapis.com --project $PROJECT_ID

# The account the nodes send as, allowed to send FCM messages.
gcloud iam service-accounts create dsm-fcm-sender --project $PROJECT_ID
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:dsm-fcm-sender@$PROJECT_ID.iam.gserviceaccount.com" \
  --role=roles/firebasecloudmessaging.admin
```

### 3. A CA of yours and one client certificate per node

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
  -subj "/CN=DSM node push CA" -keyout push-ca.key -out push-ca.crt
for n in 1 2 3 4 5; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=dsm-node-$n" -keyout push-client-$n.key -out push-client-$n.csr
  openssl x509 -req -in push-client-$n.csr -CA push-ca.crt -CAkey push-ca.key \
    -CAcreateserial -days 390 -out push-client-$n.crt
done
```

Google accepts a leaf lifetime of at most 390 days. Keep `push-ca.key` off the
nodes.

### 4. The workload identity pool, trusting that CA

```bash
gcloud iam workload-identity-pools create dsm-nodes --location=global --project $PROJECT_ID
ROOT=$(awk '{printf "%s\\n", $0}' push-ca.crt)
cat > trust_store.yaml <<EOF
trustStore:
  trustAnchors:
  - pemCertificate: "$ROOT"
EOF
gcloud iam workload-identity-pools providers create-x509 dsm-nodes-x509 \
  --location=global --workload-identity-pool=dsm-nodes --project $PROJECT_ID \
  --trust-store-config-path=trust_store.yaml \
  --attribute-mapping="google.subject=assertion.subject.dn.cn"
gcloud iam service-accounts add-iam-policy-binding \
  dsm-fcm-sender@$PROJECT_ID.iam.gserviceaccount.com --project $PROJECT_ID \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/dsm-nodes/*"
```

### 5. On each node

Copy `push-client-$n.crt` and `push-client-$n.key` to `/certs/push-client.crt`
and `/certs/push-client.key`, readable by the node only. Then add to its
config:

```toml
[push.fcm]
project_id = "<project id>"
workload_identity_provider = "//iam.googleapis.com/projects/<project number>/locations/global/workloadIdentityPools/dsm-nodes/providers/dsm-nodes-x509"
service_account = "dsm-fcm-sender@<project id>.iam.gserviceaccount.com"
client_cert_path = "/certs/push-client.crt"
client_key_path = "/certs/push-client.key"
```

On start, the node logs `push configured: Android doorbells are rung through
Firebase Cloud Messaging`. A missing file or malformed PEM stops it at
start-up with the reason. A node without `[push.fcm]` and `[push.apns]` serves
no doorbell route, and its devices keep their waits. A node with only one of
them answers a doorbell for the other service `404`, and that phone keeps its
waits.

### 6. APNs, for iPhones

No signing here either: the node uses Apple's **certificate-based connection
to APNs**, a TLS client certificate Apple issues for the app, not a `.p8` key
(which would make the node sign a JWT and read the clock).

1. The app's App ID (`com.dsm.wallet`) needs the Push Notifications
   capability, in the Apple Developer account that signs the app.
2. In Certificates, Identifiers & Profiles, create an **Apple Push
   Notification service SSL (Sandbox & Production)** certificate for that App
   ID, from a certificate signing request made on your Mac. Download it and
   export it with its private key from Keychain Access as a `.p12`.
3. Convert it to PEM:

```bash
openssl pkcs12 -in apns.p12 -clcerts -nokeys -out apns-provider.crt
openssl pkcs12 -in apns.p12 -nocerts -nodes -out apns-provider.key
```

4. On each node, copy them to `/certs/apns-provider.crt` and
   `/certs/apns-provider.key`, readable by the node only, and add:

```toml
[push.apns]
topic = "com.dsm.wallet"
client_cert_path = "/certs/apns-provider.crt"
client_key_path = "/certs/apns-provider.key"
# endpoint = "https://api.sandbox.push.apple.com"   # for phones running a development build
```

A development build of the app (Xcode, TestFlight not included) gets a
**sandbox** device token, which only `api.sandbox.push.apple.com` accepts; the
production endpoint answers it `BadDeviceToken`, and the node takes that
doorbell down (the phone keeps its waits while open). A fleet serving
development phones names the sandbox endpoint; one serving App Store or
TestFlight builds names none (production is the default). The provider
certificate is valid for both and lasts a year: renew it before it ends.

## Tests

- `dsm_storage_node/tests/push_doorbell.rs`: the node's app over Postgres
  pushes through its own client to Google's three endpoints, served by the
  test on a local port over mutual TLS (`tests/common/google_push.rs`). It
  checks:
  - one push per delivery on a registered spool;
  - none on an unregistered spool;
  - no device replaces or removes another's doorbell;
  - a refused access token is made again;
  - a token FCM has forgotten takes its doorbell down;
  - a node without `[push.fcm]` serves no doorbell;
  - an iPhone's doorbell rings through APNs (`tests/common/apple_push.rs`:
    HTTP/2, a provider certificate from the CA it trusts), as one background
    push per delivery carrying only `content-available`, and nothing through
    Firebase;
  - an iPhone whose app Apple says is gone (`410`) takes its doorbell down;
  - a node without `[push.apns]` answers an iPhone's doorbell `404`, and a
    device token that is not one `400`.
- `dsm_sdk/src/sdk/inbox_doorbell_tests.rs`: a booted pair on five nodes. It
  checks:
  - the recipient's doorbell stands on every node for exactly its planned
    routes;
  - off screen it is `Ringing` and holds no wait;
  - a transfer rings its token, and the push carries nothing;
  - the push-woken sync takes the transfer;
  - the doorbells follow the moved routes;
  - an iPhone's doorbell stands on every node through APNs with its device
    token, a transfer rings Apple's endpoint for its device and nothing
    through Firebase, and the wake the iOS host calls runs the sync and waits
    for it.
