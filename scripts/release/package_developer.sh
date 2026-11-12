#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# What a developer plugs in with besides the host, as one release archive
# (the same on every platform; install.sh unpacks it):
#
#   <out>/dsm-developer-<version>.tar.gz
#     dsm-developer-<version>/clients/dsm-app-client-<version>.tgz
#         the TypeScript client, built (its protobuf types are committed), for `npm install <file>`
#     dsm-developer-<version>/clients/dsm_app_client-<python version>-py3-none-any.whl
#         the Python client, its protobuf types inside, for `pip install <file>`
#     dsm-developer-<version>/dsm-app-client/
#         the TypeScript client with its one dependency, which the `dsm-app` and
#         `dsm-dev-wallet` commands run from
#     dsm-developer-<version>/connect-starter/
#         the starter app (examples/connect-starter), built, with its dependencies
#     dsm-developer-<version>/examples/
#         the Python client's examples (first_payment.py, account_status.py)
#
# Every dependency inside comes from the repo's lockfiles, so the archive's
# checksum covers all of it.
#
# usage: scripts/release/package_developer.sh <version> <out-dir>
# Needs Node.js 20+, npm, and Python 3.10+ with pip.

set -euo pipefail

VERSION="$1"
OUT="$2"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NAME="dsm-developer-$VERSION"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/stage/$NAME"
mkdir -p "$STAGE/clients" "$OUT"
OUT="$(cd "$OUT" && pwd)"
npm_quiet() { npm "$@" --no-audit --no-fund --loglevel=error; }

# The versions must agree: the release names one.
ts_version="$(node -p "require('$REPO/clients/typescript/package.json').version")"
[ "$ts_version" = "$VERSION" ] || { echo "clients/typescript is $ts_version, not $VERSION" >&2; exit 1; }

echo "[developer] the TypeScript client"
(cd "$REPO/clients/typescript" && npm_quiet ci && npm run --silent build)
(cd "$REPO/clients/typescript" && npm pack --silent --pack-destination "$STAGE/clients" >/dev/null)
[ -f "$STAGE/clients/dsm-app-client-$VERSION.tgz" ] || { echo "npm pack made no dsm-app-client-$VERSION.tgz" >&2; exit 1; }
# Listed to a file first: grep -q stops reading early, which fails tar under pipefail.
tar -tzf "$STAGE/clients/dsm-app-client-$VERSION.tgz" >"$WORK/packed.txt"
grep -qx 'package/dist/generated/dsm_app_pb.js' "$WORK/packed.txt" \
    || { echo "the packed TypeScript client has no dist/generated/dsm_app_pb.js" >&2; exit 1; }
# The commands' copy: the packed client and its production dependencies, by the lockfile.
mkdir -p "$WORK/cli"
tar -C "$WORK/cli" -xzf "$STAGE/clients/dsm-app-client-$VERSION.tgz"
cp "$REPO/clients/typescript/package-lock.json" "$WORK/cli/package/"
(cd "$WORK/cli/package" && npm_quiet ci --omit=dev --ignore-scripts)
mv "$WORK/cli/package" "$STAGE/dsm-app-client"

echo "[developer] the Python client"
python3 -m pip wheel --quiet --disable-pip-version-check --no-deps --wheel-dir "$WORK/wheel" "$REPO/clients/python"
wheel="$(ls "$WORK"/wheel/dsm_app_client-*-py3-none-any.whl)"
python3 - "$wheel" "$VERSION" <<'EOF'
import sys, zipfile
names = zipfile.ZipFile(sys.argv[1]).namelist()
if "dsm_app_client/generated/dsm_app_pb2.py" not in names:
    sys.exit("the wheel has no dsm_app_client/generated/dsm_app_pb2.py")
# 0.1.0-beta.4 is 0.1.0b4 in Python's spelling.
want = sys.argv[2].replace("-beta.", "b").replace("-alpha.", "a").replace("-rc.", "rc")
if f"dsm_app_client-{want}-py3-none-any.whl" not in sys.argv[1]:
    sys.exit(f"the wheel {sys.argv[1]} is not version {want}")
EOF
cp "$wheel" "$STAGE/clients/"
mkdir -p "$STAGE/examples"
cp "$REPO"/clients/python/examples/*.py "$STAGE/examples/"

echo "[developer] the starter app"
(cd "$REPO/examples/connect-starter" && npm_quiet ci && npm run --silent build)
# Pruned in a copy laid out as the repo is, so its link to the client resolves.
mkdir -p "$WORK/tree/examples" "$WORK/tree/clients"
cp -R "$REPO/clients/typescript" "$WORK/tree/clients/typescript"
cp -R "$REPO/examples/connect-starter" "$WORK/tree/examples/connect-starter"
(cd "$WORK/tree/examples/connect-starter" && npm_quiet prune --omit=dev)
mkdir -p "$STAGE/connect-starter"
for f in package.json package-lock.json page.html README.md dist node_modules; do
    cp -R "$WORK/tree/examples/connect-starter/$f" "$STAGE/connect-starter/"
done
# The client it uses: the same copy the commands run, not a link into the repo.
rm -rf "$STAGE/connect-starter/node_modules/dsm-app-client"
cp -R "$STAGE/dsm-app-client" "$STAGE/connect-starter/node_modules/dsm-app-client"

cp "$REPO/LICENSE-MIT" "$REPO/LICENSE-APACHE" "$STAGE/"
tar -C "$WORK/stage" -cf - "$NAME" | gzip -n -9 >"$OUT/$NAME.tar.gz"
echo "[developer] $OUT/$NAME.tar.gz"
