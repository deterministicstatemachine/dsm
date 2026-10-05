#!/usr/bin/env bash
# Pre-audit item 16: no component a release build declares may be started by
# another app except the launcher activity. An exported component is an entry
# point any installed app can call with intents and extras of its choosing; a
# component that can do something irreversible or security-sensitive must not
# be one. Debug-only tools are declared in src/debug/AndroidManifest.xml, which
# a release build does not merge.
#
# Amended by the owner 2026-10-04 (DSM Amendment A11): the launcher may also
# answer one link filter, `dsm:` URIs whose scheme-specific part starts
# `connect/v1:`, so an application on the same phone can hand the wallet a
# connect code. The link carries a code only; the wallet reads it when the
# player asks. No other filter, scheme or data is admitted.
set -euo pipefail
echo "=== android: the release manifest exports the launcher only (MAIN, and dsm:connect/v1: links) ==="

manifest=dsm_client/android/app/src/main/AndroidManifest.xml
[[ -f "$manifest" ]] || { echo "[FAIL] $manifest is missing"; exit 1; }

python3 - "$manifest" <<'PY'
import sys
import xml.etree.ElementTree as ET

ANDROID = "{http://schemas.android.com/apk/res/android}"
LAUNCHER = "com.dsm.wallet.ui.MainActivity"
manifest = ET.parse(sys.argv[1]).getroot()
application = manifest.find("application")
problems = []
for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
    for component in application.findall(kind):
        name = component.get(ANDROID + "name", "")
        exported = component.get(ANDROID + "exported")
        filters = component.findall("intent-filter")
        if exported is None:
            problems.append(f"{kind} {name} does not state android:exported")
            continue
        if exported == "true" and name != LAUNCHER:
            problems.append(f"{kind} {name} is exported")
        if name == LAUNCHER:
            main_filters = 0
            link_filters = 0
            for f in filters:
                actions = {a.get(ANDROID + "name") for a in f.findall("action")}
                categories = {c.get(ANDROID + "name") for c in f.findall("category")}
                data = [
                    {k[len(ANDROID):] if k.startswith(ANDROID) else k: v for k, v in d.attrib.items()}
                    for d in f.findall("data")
                ]
                if (
                    actions == {"android.intent.action.MAIN"}
                    and categories == {"android.intent.category.LAUNCHER"}
                    and not data
                ):
                    main_filters += 1
                elif (
                    actions == {"android.intent.action.VIEW"}
                    and categories
                    == {"android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"}
                    and data == [{"scheme": "dsm", "sspPrefix": "connect/v1:"}]
                ):
                    link_filters += 1
                else:
                    problems.append(
                        f"the launcher answers a filter item 16 does not admit: actions {sorted(actions)}, "
                        f"categories {sorted(categories)}, data {data}"
                    )
            if main_filters != 1:
                problems.append(f"the launcher answers MAIN in {main_filters} filters, not one")
            if link_filters > 1:
                problems.append(f"the launcher declares {link_filters} connect-link filters, not at most one")
for problem in problems:
    print(f"[FAIL] {problem}")
if problems:
    sys.exit(1)
print("  ✓ only the launcher is exported; it answers MAIN, and dsm:connect/v1: links at most")
PY
