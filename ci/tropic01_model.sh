#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Install Tropic Square's TROPIC01 model into a throwaway directory, for the rehearsal in
# crates/dsm-anchor-chip/tests. The wheel and the chip configuration are fetched from Tropic Square's
# own repositories and each is checked against its pinned digest, the wheel's being the one their
# installer pins. Nothing is kept in this repository. Prints the environment the tests read.
#
# usage: ci/tropic01_model.sh <directory> >> "$GITHUB_ENV"
set -euo pipefail

WHEEL_URL="https://github.com/tropicsquare/ts-tvl/releases/download/2.4/tvl-2.4-py3-none-any.whl"
WHEEL_SHA256="aaceecc3cdf408b94784ae6b5229bedda974d74530267ad25e0e0a61ad2e526c"
LIBTROPIC_COMMIT="756c8ee898ed61b12272ecb22b213edf97aab751"
CFG_URL="https://raw.githubusercontent.com/tropicsquare/libtropic/${LIBTROPIC_COMMIT}/scripts/tropic01_model/model_cfg.yml"
CFG_SHA256="e6b0c32e2b851ef1c6ff3853fb0021e311358c3d96630dc59432c586007187b9"

dir="${1:?usage: ci/tropic01_model.sh <directory>}"
mkdir -p "$dir"

fetch() { # URL FILE SHA256
  curl -fsSL "$1" -o "$2"
  echo "$3  $2" | sha256sum -c - >&2
}

fetch "$WHEEL_URL" "$dir/tvl-2.4-py3-none-any.whl" "$WHEEL_SHA256"
fetch "$CFG_URL" "$dir/model_cfg.yml" "$CFG_SHA256"

python3 -m venv "$dir/venv" >&2
"$dir/venv/bin/pip" -q install "$dir/tvl-2.4-py3-none-any.whl" >&2

echo "DSM_TROPIC01_MODEL_SERVER=$dir/venv/bin/model_server"
echo "DSM_TROPIC01_MODEL_CFG=$dir/model_cfg.yml"
