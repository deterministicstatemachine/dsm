#!/usr/bin/env bash
# DSM storage node, on the machine that runs it. Run as root. Operators never run
# this by hand: launch_on_google_cloud.sh runs it for them.
#
#   node_host.sh install <seat 1-5> <public IP>   Set the node up and start it. Safe to repeat.
#   node_host.sh code                             Print this node's join code again.
#   node_host.sh join                             Take the published member list, once.
#   node_host.sh status                           Say how the node is doing.
#   node_host.sh update                           Move to the current beta image.
#
# Nothing here ever deletes the node's database or replaces its keys. The database
# holds this node's register: a node that loses it can never come back as the same
# member (config/production.toml), so a repeated install keeps what it finds.
#
# The operator's CA key is made here and never leaves this machine. Everything the
# join code carries is public: the seat, the address, the register incarnation and
# the CA certificate.
#
# These can be set to run against another source, as the end-to-end run does:
#   DSM_SOURCE_BASE  where this directory's files are served from
#   DSM_SET_URL      where the published member list is served from
#   DSM_NODE_IMAGE   the image to run
set -euo pipefail

REPO="https://github.com/deterministicstatemachine/dsm"
SOURCE_BASE="${DSM_SOURCE_BASE:-https://raw.githubusercontent.com/deterministicstatemachine/dsm/main/dsm_storage_node}"
SET_URL="${DSM_SET_URL:-$REPO/releases/download/public-beta-set/public_beta_set.json}"
HOME_DIR=/opt/dsm-storage
PROJECT=dsm-storage
COMPOSE_FILE="$HOME_DIR/docker-compose.node.yml"
CONFIG="$HOME_DIR/config/node.toml"
SEAT_FILE="$HOME_DIR/seat"
IP_FILE="$HOME_DIR/public_ip"
INCARNATION_FILE="$HOME_DIR/register_incarnation"

say() { printf '%s\n' "$*"; }
die() { printf '\nThat did not work: %s\n' "$*" >&2; exit 1; }

compose() { docker compose -p "$PROJECT" --project-directory "$HOME_DIR" -f "$COMPOSE_FILE" "$@"; }
node_id() { printf 'dsm-node-%s' "$(cat "$SEAT_FILE")"; }

install_docker() {
    command -v docker >/dev/null && docker compose version >/dev/null 2>&1 && return 0
    say "Installing Docker..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg lsb-release python3 >/dev/null
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu %s stable\n' \
        "$(dpkg --print-architecture)" "$(lsb_release -cs)" > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
    systemctl enable --now docker >/dev/null
}

make_identity() {
    local id ip
    id="$(node_id)"
    ip="$(cat "$IP_FILE")"
    mkdir -p "$HOME_DIR/ca" "$HOME_DIR/certs" "$HOME_DIR/config"
    chmod 700 "$HOME_DIR/ca"
    if [ ! -f "$HOME_DIR/ca/ca.key" ]; then
        say "Making your own certificate authority..."
        (umask 077 && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
            -out "$HOME_DIR/ca/ca.key" 2>/dev/null)
        openssl req -new -x509 -days 3650 -key "$HOME_DIR/ca/ca.key" \
            -subj "/O=DSM storage operator/CN=$id CA" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -out "$HOME_DIR/ca/ca.crt"
    fi
    if [ ! -f "$HOME_DIR/certs/node.key" ]; then
        (umask 077 && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
            -out "$HOME_DIR/certs/node.key" 2>/dev/null)
    fi
    # The certificate names this member and its address. A repeated install at a
    # changed address issues a new one under the same CA.
    if [ ! -f "$HOME_DIR/certs/node.crt" ] \
        || ! openssl x509 -in "$HOME_DIR/certs/node.crt" -noout -checkip "$ip" 2>/dev/null | grep -q 'does match'; then
        local extensions
        extensions="$(mktemp)"
        printf 'subjectAltName=IP:%s,DNS:%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' \
            "$ip" "$id" > "$extensions"
        openssl req -new -key "$HOME_DIR/certs/node.key" -subj "/O=DSM storage operator/CN=$id" \
            | openssl x509 -req -days 3650 -CA "$HOME_DIR/ca/ca.crt" -CAkey "$HOME_DIR/ca/ca.key" \
                -CAcreateserial -extfile "$extensions" -out "$HOME_DIR/certs/node.crt" 2>/dev/null
        rm -f "$extensions"
    fi
    if [ ! -f "$HOME_DIR/.env" ]; then
        local password
        password="$(openssl rand -hex 24)"
        (umask 077 && cat > "$HOME_DIR/.env" <<ENV
POSTGRES_DB=dsm_storage
POSTGRES_USER=dsm
POSTGRES_PASSWORD=$password
DSM_PORT=8080
DSM_NODE_IMAGE=${DSM_NODE_IMAGE:-ghcr.io/deterministicstatemachine/dsm-storage-node:beta}
RUST_LOG=info
ENV
)
    fi
}

write_config() {
    [ -f "$CONFIG" ] && return 0
    local template password
    template="$(mktemp)"
    curl -fsSL "$SOURCE_BASE/config/production.toml" -o "$template" \
        || die "could not download the node's settings."
    password="$(sed -n 's/^POSTGRES_PASSWORD=//p' "$HOME_DIR/.env")"
    (umask 077 && sed -e "s|__NODE_ID__|$(node_id)|g" \
        -e "s|__LISTEN_ADDR__|0.0.0.0|g" \
        -e "s|__DATABASE_URL__|postgresql://postgres:5432/dsm_storage?user=dsm\&password=$password\&sslmode=disable|g" \
        "$template" > "$CONFIG")
    rm -f "$template"
}

image() { sed -n 's/^DSM_NODE_IMAGE=//p' "$HOME_DIR/.env"; }

# The key and the settings holding the database password are readable by the
# user the image runs as and nobody else.
hand_files_to_the_node() {
    local uid gid
    uid="$(docker run --rm --entrypoint id "$(image)" -u)"
    gid="$(docker run --rm --entrypoint id "$(image)" -g)"
    chown "$uid:$gid" "$HOME_DIR/certs/node.key" "$CONFIG"
    chmod 600 "$HOME_DIR/certs/node.key" "$CONFIG"
}

wait_for_health() {
    local tries=0
    until curl -fsS --cacert "$HOME_DIR/ca/ca.crt" --resolve "$(node_id):8080:127.0.0.1" \
            "https://$(node_id):8080/api/v2/health" >/dev/null 2>&1; do
        tries=$((tries + 1))
        [ "$tries" -lt 40 ] || return 1
        sleep 3
    done
}

read_incarnation() {
    [ -s "$INCARNATION_FILE" ] && return 0
    local tries=0 found=""
    while [ -z "$found" ] && [ "$tries" -lt 40 ]; do
        found="$(compose logs --no-color storage-node 2>/dev/null \
            | grep -a 'register incarnation for node' | grep -aoE '[0-9A-Z]{52}' | tail -1 || :)"
        [ -n "$found" ] || sleep 3
        tries=$((tries + 1))
    done
    [ -n "$found" ] || die "the node did not start. Logs: $(compose logs --no-color --tail 15 storage-node 2>&1)"
    printf '%s\n' "$found" > "$INCARNATION_FILE"
}

print_code() {
    local code
    code="$(python3 - "$(cat "$SEAT_FILE")" "$(cat "$IP_FILE")" "$(cat "$INCARNATION_FILE")" "$HOME_DIR/ca/ca.crt" <<'PY'
import base64, gzip, json, pathlib, sys
seat, ip, incarnation, ca = sys.argv[1:5]
body = {
    "seat": int(seat),
    "endpoint": f"https://{ip}:8080",
    "register_incarnation": incarnation,
    "ca_cert": pathlib.Path(ca).read_text(),
}
print("DSMNODE1:" + base64.b64encode(gzip.compress(json.dumps(body).encode(), mtime=0)).decode())
PY
)"
    printf '\n%s\n' "----- YOUR NODE'S CODE: copy everything between the lines -----"
    printf '%s\n' "$code"
    printf '%s\n\n' "---------------------------------------------------------------"
}

# Checks the node for the published member list every few minutes until it has
# taken it once. Where systemd is not running, `join` is run by hand.
install_join_timer() {
    [ -d /run/systemd/system ] || return 0
    install -m 0755 "${BASH_SOURCE[0]}" "$HOME_DIR/node_host.sh"
    cat > /etc/systemd/system/dsm-node-join.service <<UNIT
[Unit]
Description=DSM storage node: take the published member list
After=docker.service

[Service]
Type=oneshot
Environment=DSM_SET_URL=$SET_URL
ExecStart=$HOME_DIR/node_host.sh join
UNIT
    cat > /etc/systemd/system/dsm-node-join.timer <<UNIT
[Unit]
Description=DSM storage node: look for the published member list

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
UNIT
    systemctl daemon-reload
    systemctl enable --now dsm-node-join.timer >/dev/null
}

install_node() {
    [ "$(id -u)" -eq 0 ] || die "run this as root."
    local seat="${1:-}" ip="${2:-}"
    case "$seat" in 1|2|3|4|5) ;; *) die "the seat number must be 1 to 5." ;; esac
    printf '%s' "$ip" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || die "'$ip' is not an IP address."
    mkdir -p "$HOME_DIR"
    if [ -f "$SEAT_FILE" ] && [ "$(cat "$SEAT_FILE")" != "$seat" ]; then
        die "this machine already runs seat $(cat "$SEAT_FILE"), not seat $seat."
    fi
    printf '%s\n' "$seat" > "$SEAT_FILE"
    printf '%s\n' "$ip" > "$IP_FILE"

    install_docker
    command -v python3 >/dev/null || die "python3 is missing."
    make_identity
    curl -fsSL "$SOURCE_BASE/deploy/docker-compose.node.yml" -o "$COMPOSE_FILE" \
        || die "could not download the node's setup file."
    write_config
    if ! docker image inspect "$(image)" >/dev/null 2>&1; then
        say "Downloading the node (a minute or two)..."
        docker pull -q "$(image)" >/dev/null \
            || die "could not download $(image). Tell the person who invited you."
    fi
    hand_files_to_the_node
    say "Starting the node..."
    local output
    output="$(compose up -d --wait --wait-timeout 180 postgres 2>&1)" || die "its database did not start. $output"
    output="$(compose up -d storage-node 2>&1)" || die "the node did not start. $output"
    read_incarnation
    wait_for_health || die "the node started but does not answer. Logs: $(compose logs --no-color --tail 15 storage-node 2>&1)"
    install_join_timer
    print_code
}

# Takes the published member list once, and never again: a set is immutable for
# the lifetime of every vault born under it (config/production.toml). A list that
# does not name this node exactly as this node is, is not this node's set.
join_set() {
    [ "$(id -u)" -eq 0 ] || die "run this as root."
    if grep -q '^\[storage_set\]' "$CONFIG"; then
        command -v systemctl >/dev/null && systemctl disable --now dsm-node-join.timer >/dev/null 2>&1 || :
        say "This node has already taken its member list."
        return 0
    fi
    local list block
    list="$(mktemp)"
    block="$(mktemp)"
    if ! curl -fsSL "$SET_URL" -o "$list" 2>/dev/null; then
        rm -f "$list" "$block"
        say "The member list is not published yet."
        return 0
    fi
    if ! python3 - "$list" "$(node_id)" "$(cat "$INCARNATION_FILE")" "$HOME_DIR/ca/ca.crt" "https://$(cat "$IP_FILE"):8080" > "$block" <<'PY'
import json, pathlib, re, sys
listed, own, incarnation, ca, endpoint = sys.argv[1:6]
members = json.loads(pathlib.Path(listed).read_text())["members"]
if sorted(m.get("id", "") for m in members) != [f"dsm-node-{seat}" for seat in range(1, 6)]:
    sys.exit("the list does not name exactly the five seats")
shapes = {
    "id": r"dsm-node-[1-5]",
    "register_incarnation": r"[0-9A-Z]{52}",
    "endpoint": r"https://\d+\.\d+\.\d+\.\d+:8080",
    "ca_cert": r"-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]{1,76}\n)+-----END CERTIFICATE-----\n",
}
for m in members:
    for field, shape in shapes.items():
        if not isinstance(m.get(field), str) or not re.fullmatch(shape, m[field]):
            sys.exit(f"the list's {field} is not in the expected form")
mine = [m for m in members if m["id"] == own]
if len(mine) != 1:
    sys.exit(f"the list does not name {own}")
if mine[0]["register_incarnation"] != incarnation:
    sys.exit("the list names another register incarnation for this node")
if mine[0]["ca_cert"] != pathlib.Path(ca).read_text():
    sys.exit("the list names another CA for this node")
if mine[0]["endpoint"] != endpoint:
    sys.exit("the list names another address for this node")
print("\n[storage_set]")
for m in members:
    print(f'\n[[storage_set.members]]\nid = "{m["id"]}"')
    print(f'register_incarnation = "{m["register_incarnation"]}"')
    print(f'endpoint = "{m["endpoint"]}"')
    print(f'ca_cert = """\n{m["ca_cert"]}"""')
PY
    then
        rm -f "$list" "$block"
        die "the published member list does not match this node. Tell the person who invited you."
    fi
    local kept
    kept="$(mktemp)"
    cp -p "$CONFIG" "$kept"
    cat "$block" >> "$CONFIG"
    rm -f "$list" "$block"
    compose restart storage-node >/dev/null 2>&1
    if wait_for_health && compose logs --no-color --tail 200 storage-node 2>/dev/null | grep -aq 'storage set configured'; then
        rm -f "$kept"
        command -v systemctl >/dev/null && systemctl disable --now dsm-node-join.timer >/dev/null 2>&1 || :
        say "Your node has joined. Nothing more to do."
        return 0
    fi
    # Back to serving as it was: a list it refused must not keep it down.
    local logs
    logs="$(compose logs --no-color --tail 15 storage-node 2>&1)"
    cp -p "$kept" "$CONFIG"
    rm -f "$kept"
    compose restart storage-node >/dev/null 2>&1
    die "the node refused the member list and went back to how it was. Logs: $logs"
}

status() {
    say "Seat:     $(cat "$SEAT_FILE")"
    say "Address:  https://$(cat "$IP_FILE"):8080"
    if wait_for_health; then say "Running:  yes"; else say "Running:  NO"; fi
    if grep -q '^\[storage_set\]' "$CONFIG"; then
        say "Joined:   yes"
        compose logs --no-color storage-node 2>/dev/null | grep -a 'storage set configured' \
            | tail -1 | sed -E 's/.*id=/Set id:   /' || :
    else
        say "Joined:   not yet. It joins by itself once the member list is published."
    fi
    say "Disk:     $(df -h "$HOME_DIR" | awk 'NR==2 {print $5 " used of " $2}')"
}

update_node() {
    [ "$(id -u)" -eq 0 ] || die "run this as root."
    say "Downloading the current beta image..."
    docker pull -q "$(image)" >/dev/null || die "could not download $(image)."
    hand_files_to_the_node
    compose up -d --no-deps storage-node >/dev/null 2>&1 || die "the node did not start."
    wait_for_health || die "the node does not answer. Logs: $(compose logs --no-color --tail 15 storage-node 2>&1)"
    say "Your node is up to date."
}

case "${1:-}" in
    install) shift; install_node "$@" ;;
    code) print_code ;;
    join) join_set ;;
    status) status ;;
    update) update_node ;;
    *) sed -n 2,9p "$0"; exit 2 ;;
esac
