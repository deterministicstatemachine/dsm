#!/usr/bin/env bash
# Pre-audit item 16: no component a release build declares may be started by
# another app except the launcher activity. An exported component is an entry
# point any installed app can call with intents and extras of its choosing; a
# component that can do something irreversible or security-sensitive must not
# be one. Debug-only tools are declared in src/debug/AndroidManifest.xml, which
# a release build does not merge.
set -euo pipefail
echo "=== android: the release manifest exports the launcher only ==="

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
            actions = {a.get(ANDROID + "name") for f in filters for a in f.findall("action")}
            if actions != {"android.intent.action.MAIN"}:
                problems.append(f"the launcher answers {sorted(actions)}, not MAIN alone")
            for f in filters:
                if f.findall("data"):
                    problems.append("the launcher declares a data filter (a deep link)")
for problem in problems:
    print(f"[FAIL] {problem}")
if problems:
    sys.exit(1)
print("  ✓ only the launcher is exported, and it answers MAIN alone")
PY
