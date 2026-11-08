#!/usr/bin/env bash
# DSM Storage Node: wipe every member of the GCP set and bring it up on a new image.
#
# IRREVERSIBLE: every member's database is deleted, and each mints a new register
# incarnation (see the two-phase bring-up in the node's config). The storage set id changes,
# so every client pinned to the old set stops working until its pins are updated.
# Only the storage project at /opt/dsm-storage is touched: anything else on a host keeps running.
#
# Usage:
#   docker build --platform linux/amd64 -f dsm_storage_node/Dockerfile.cloud -t dsm-storage-node:reprovision .
#   ./reprovision_gcp.sh --yes-delete-every-member-database
#
# It prints each member's new incarnation. Pin them in dsm::economic::register,
# dsm_sdk::sdk::storage_set and the client env config.
set -euo pipefail

[ "${1:-}" = "--yes-delete-every-member-database" ] || { sed -n 2,14p "$0"; exit 2; }

ZONE="us-central1-b"
DEPLOY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
NODES=(1 2 3 4 5)

remote() { # member, command
    gcloud compute ssh "dsm-storage-node-$1" --zone "$ZONE" --quiet --command "$2" 2>&1
}

echo "==> Saving the image"
docker image inspect dsm-storage-node:reprovision --format '{{.Architecture}}' | grep -qx amd64
docker save dsm-storage-node:reprovision | gzip -1 > "$WORK/image.tar.gz"
ls -la "$WORK/image.tar.gz"

echo "==> Copying it to every member"
for n in "${NODES[@]}"; do
    gcloud compute scp --zone "$ZONE" --quiet "$WORK/image.tar.gz" "$DEPLOY/docker-compose.node.yml" \
        "dsm-storage-node-$n:/tmp/" > /dev/null 2>&1 &
done
wait

echo "==> Phase 1: wipe, and boot with no member list, so each mints its incarnation"
for n in "${NODES[@]}"; do
    remote "$n" "set -e
        sudo docker load -i /tmp/image.tar.gz | tail -1
        sudo docker tag dsm-storage-node:reprovision dsm-storage-node:latest
        cd /opt/dsm-storage
        sudo docker compose -p dsm-storage -f docker-compose.node.yml down
        sudo docker volume rm dsm-storage_pgdata
        sudo cp config/node.toml config/node.toml.pre-reprovision-$(date -u +%Y%m%dT%H%M%SZ)
        sudo sh -c 'sed \"/^\[storage_set\]/,\\\$d\" config/node.toml > config/node.toml.phase1 && cp config/node.toml config/node.toml.phase2 && cp config/node.toml.phase1 config/node.toml'
        sudo cp /tmp/docker-compose.node.yml docker-compose.node.yml
        sudo docker compose -p dsm-storage -f docker-compose.node.yml up -d
        sudo rm -f /tmp/image.tar.gz" | tail -2 &
done
wait

echo "==> Collecting incarnations"
declare -A NEW
for n in "${NODES[@]}"; do
    for _ in $(seq 1 40); do
        NEW[$n]="$(remote "$n" "sudo docker logs dsm-storage-storage-node-1 2>&1 | grep -a 'register incarnation for node' | tail -1" |
            grep -aoE '[0-9A-Z]{52}' | tail -1 || true)"
        [ -n "${NEW[$n]}" ] && break
        sleep 3
    done
    [ -n "${NEW[$n]}" ] || { echo "dsm-node-$n logged no incarnation"; remote "$n" "sudo docker logs --tail 30 dsm-storage-storage-node-1"; exit 1; }
    echo "dsm-node-$n ${NEW[$n]}"
done

echo "==> Phase 2: the member list on every member, then restart"
for n in "${NODES[@]}"; do
    script="set -e; cd /opt/dsm-storage; sudo python3 - <<'PY'
import re
s = open('config/node.toml.phase2').read()
new = {'dsm-node-1': '${NEW[1]}', 'dsm-node-2': '${NEW[2]}', 'dsm-node-3': '${NEW[3]}', 'dsm-node-4': '${NEW[4]}', 'dsm-node-5': '${NEW[5]}'}
for member, value in new.items():
    s, count = re.subn(r'(id = \"' + member + r'\"\nregister_incarnation = \")[0-9A-Z]{52}', lambda m: m.group(1) + value, s)
    assert count == 1, member
open('config/node.toml', 'w').write(s)
PY
sudo docker compose -p dsm-storage -f docker-compose.node.yml restart storage-node"
    remote "$n" "$script" | tail -1 &
done
wait
sleep 20

echo "==> Checking"
for n in "${NODES[@]}"; do
    remote "$n" "curl -sk -o /dev/null -w 'dsm-node-$n health %{http_code} ' https://localhost:8080/api/v2/health
        sudo docker ps --filter name=dsm-storage-storage-node-1 --format '{{.Status}}'
        sudo docker logs dsm-storage-storage-node-1 2>&1 | grep -aiE 'set id|storage set|refus' | tail -2"
done
rm -f "$WORK/image.tar.gz"
rmdir "$WORK"
echo "REPROVISION-DONE"
