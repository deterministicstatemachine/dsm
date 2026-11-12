#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run before a job's first apt step on a GitHub-hosted runner.
#
# On 2026-11-11, from 14:16 UTC, GitHub's runners stopped resolving Ubuntu's
# package servers ("Temporary failure resolving 'azure.archive.ubuntu.com'")
# while every other name still resolved. Every job that installs packages
# failed at that step, here and in other repositories, and GitHub posted no
# incident.
#
# When the runner resolves those servers, this changes nothing. When it does
# not, it points the runner's resolver at public DNS (Cloudflare and Google)
# for the rest of the job and says so in the log; a Docker build later in the
# job resolves through the same servers. If the servers still do not resolve,
# it fails here with that reason, rather than in apt.
set -euo pipefail

HOSTS="azure.archive.ubuntu.com archive.ubuntu.com security.ubuntu.com"
PUBLIC_DNS="1.1.1.1 8.8.8.8"

resolves() {
    local host
    for host in $HOSTS; do
        timeout 15 getent ahostsv4 "$host" >/dev/null || return 1
    done
}

if resolves; then
    exit 0
fi

echo "::warning::This runner cannot resolve Ubuntu's package servers; resolving through public DNS ($PUBLIC_DNS) for the rest of this job."
link=""
if command -v ip >/dev/null; then
    link=$(ip -4 route show default | awk 'NR == 1 { print $5 }')
fi
if command -v resolvectl >/dev/null && [ -n "$link" ]; then
    # systemd-resolved, as on GitHub's Ubuntu runners: the link's servers.
    # shellcheck disable=SC2086 # one argument per server
    sudo resolvectl dns "$link" $PUBLIC_DNS
    sudo resolvectl flush-caches
else
    # No resolved: the file itself. A symlink is replaced; a bind-mounted
    # file (as in a container) is rewritten in place.
    if [ -L /etc/resolv.conf ]; then
        sudo rm -f /etc/resolv.conf
    fi
    # shellcheck disable=SC2086 # one line per server
    printf 'nameserver %s\n' $PUBLIC_DNS | sudo tee /etc/resolv.conf >/dev/null
fi

for _ in 1 2 3 4 5 6; do
    if resolves; then
        echo "Ubuntu's package servers resolve through public DNS."
        exit 0
    fi
    sleep 5
done
echo "::error::Ubuntu's package servers do not resolve through public DNS either."
exit 1
