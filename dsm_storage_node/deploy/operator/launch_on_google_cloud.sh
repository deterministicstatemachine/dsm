#!/usr/bin/env bash
# DSM storage node: the one script an operator runs, in Google Cloud Shell.
# RUN_A_NODE.md is the guide. It creates everything itself, and running it again
# reuses what is already there.
#
#   launch_on_google_cloud.sh start <seat 1-5>   Create the machine and start the node.
#   launch_on_google_cloud.sh code               Show this node's code again.
#   launch_on_google_cloud.sh status             Say how the node is doing.
#   launch_on_google_cloud.sh update             Move to the current beta image.
set -euo pipefail

SOURCE_BASE="${DSM_SOURCE_BASE:-https://raw.githubusercontent.com/deterministicstatemachine/dsm/main/dsm_storage_node}"
VM=dsm-storage-node
ADDRESS=dsm-storage-node-ip
TAG=dsm-storage-node
REGION="${DSM_REGION:-us-central1}"
ZONE="$REGION-b"
MACHINE_TYPE="${DSM_MACHINE_TYPE:-e2-medium}"
DISK_GB="${DSM_DISK_GB:-50}"
# Where Google's own "SSH" connections come from (Identity-Aware Proxy).
IAP_RANGE=35.235.240.0/20

LOG="$(mktemp)"
say() { printf '%s\n' "$*"; }
die() {
    printf '\nThat did not work: %s\n' "$*" >&2
    if [ -s "$LOG" ]; then
        printf '\nDetails, for the person helping you:\n' >&2
        tail -15 "$LOG" >&2
    fi
    exit 1
}
quiet() { "$@" >>"$LOG" 2>&1; }
exists() { "$@" >/dev/null 2>&1; }

choose_project() {
    local project
    project="$(gcloud config get-value project 2>/dev/null || :)"
    if [ -z "$project" ] || [ "$project" = "(unset)" ]; then
        local all
        all="$(gcloud projects list --format='value(projectId)' 2>>"$LOG")" \
            || die "Google did not let this script look at your account. Refresh this page, click Authorize when asked, and try again."
        [ -n "$all" ] || die "this account has no project yet. Finish the free trial sign-up (step 1 of the guide) and try again."
        project="$(printf '%s\n' "$all" | head -1)"
        if [ "$(printf '%s\n' "$all" | wc -l)" -gt 1 ]; then
            say "You have more than one Google Cloud project. Using: $project"
        fi
    fi
    gcloud config set project "$project" >>"$LOG" 2>&1
    PROJECT="$project"
    local billing
    billing="$(gcloud billing projects describe "$PROJECT" --format='value(billingEnabled)' 2>>"$LOG" || :)"
    case "$billing" in
        True|true) ;;
        *) die "project $PROJECT has no billing account, so Google will not create a machine. Finish the free trial sign-up (step 1 of the guide) and try again." ;;
    esac
}

on_the_machine() {
    gcloud compute ssh "$VM" --zone "$ZONE" --tunnel-through-iap --quiet --command "$1"
}

node_host() {
    on_the_machine "curl -fsSL '$SOURCE_BASE/deploy/operator/node_host.sh' -o /tmp/dsm_node_host.sh && sudo bash /tmp/dsm_node_host.sh $1" 2>>"$LOG"
}

create_address() {
    if ! exists gcloud compute addresses describe "$ADDRESS" --region "$REGION"; then
        quiet gcloud compute addresses create "$ADDRESS" --region "$REGION" \
            || die "Google would not reserve an address."
    fi
    PUBLIC_IP="$(gcloud compute addresses describe "$ADDRESS" --region "$REGION" --format='value(address)')"
}

# Phones and the other nodes reach port 8080. Remote shells come only through
# Google's own connection, never from the open internet.
create_firewall() {
    if ! exists gcloud compute firewall-rules describe dsm-allow-api; then
        quiet gcloud compute firewall-rules create dsm-allow-api --network default \
            --allow tcp:8080 --source-ranges 0.0.0.0/0 --target-tags "$TAG" \
            || die "Google would not open the node's port."
    fi
    if ! exists gcloud compute firewall-rules describe dsm-allow-google-ssh; then
        quiet gcloud compute firewall-rules create dsm-allow-google-ssh --network default \
            --priority 900 --allow tcp:22 --source-ranges "$IAP_RANGE" --target-tags "$TAG" \
            || die "Google would not allow its own connection to the machine."
    fi
    if ! exists gcloud compute firewall-rules describe dsm-deny-remote-shells; then
        quiet gcloud compute firewall-rules create dsm-deny-remote-shells --network default \
            --priority 1000 --action deny --rules tcp:22,tcp:3389 --source-ranges 0.0.0.0/0 --target-tags "$TAG" \
            || die "Google would not close the machine to the open internet."
    fi
}

# The node's database lives on this disk, and losing it loses this seat for good.
# So the disk outlives the machine, and the machine cannot be deleted by accident.
create_machine() {
    if exists gcloud compute instances describe "$VM" --zone "$ZONE"; then
        return 0
    fi
    quiet gcloud compute instances create "$VM" --zone "$ZONE" \
        --machine-type "$MACHINE_TYPE" \
        --image-family ubuntu-2204-lts --image-project ubuntu-os-cloud \
        --boot-disk-size "${DISK_GB}GB" --boot-disk-type pd-balanced --no-boot-disk-auto-delete \
        --address "$PUBLIC_IP" --tags "$TAG" --deletion-protection \
        || die "Google would not create the machine."
}

wait_for_machine() {
    local tries=0
    until on_the_machine "command -v curl >/dev/null" >>"$LOG" 2>&1; do
        tries=$((tries + 1))
        [ "$tries" -lt 30 ] || die "the machine was created but cannot be reached yet. Wait five minutes and paste the same line again."
        sleep 10
    done
}

start() {
    local seat="${1:-}"
    case "$seat" in 1|2|3|4|5) ;; *) die "the line you were sent should end with your seat number, 1 to 5." ;; esac
    say "Setting up your DSM node, seat $seat. This takes about five minutes. Keep this page open."
    say ""
    say "[1/5] Checking your Google Cloud account..."
    choose_project
    say "[2/5] Turning on the Google services the node needs..."
    quiet gcloud services enable compute.googleapis.com iap.googleapis.com \
        || die "Google would not turn on its services for project $PROJECT."
    say "[3/5] Reserving your node's permanent address and opening its port..."
    create_address
    create_firewall
    say "[4/5] Creating the machine..."
    create_machine
    wait_for_machine
    say "[5/5] Starting the node..."
    node_host "install $seat $PUBLIC_IP"
    say "Your node is running at https://$PUBLIC_IP:8080"
    say ""
    say "Last step: send the code above to the person who invited you."
    say "After that there is nothing to do. Your node finishes joining by itself."
}

find_machine() {
    choose_project
    exists gcloud compute instances describe "$VM" --zone "$ZONE" \
        || die "there is no node in project $PROJECT yet. Paste the line you were first sent."
}

case "${1:-}" in
    start) shift; start "$@" ;;
    code) find_machine; node_host code ;;
    status) find_machine; node_host status ;;
    update) find_machine; node_host update ;;
    *) sed -n 2,9p "$0"; exit 2 ;;
esac
rm -f "$LOG"
