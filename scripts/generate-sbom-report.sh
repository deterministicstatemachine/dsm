#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SBOM_ROOT="${PROJECT_ROOT}/sbom"
REPORT_ROOT="${PROJECT_ROOT}/reports"

usage() {
    cat <<'EOF'
Usage: scripts/generate-sbom-report.sh [--run-dir <path>]

Renders a concise report for an existing SBOM bundle. If no run directory is
provided, the latest bundle is used. If no bundle exists yet, this script
delegates to scripts/generate-sbom.sh.
EOF
}

relative_path() {
    local absolute_path="$1"
    if [[ "${absolute_path}" == "${PROJECT_ROOT}" ]]; then
        printf '.\n'
    elif [[ "${absolute_path}" == "${PROJECT_ROOT}/"* ]]; then
        printf '%s\n' "${absolute_path#"${PROJECT_ROOT}/"}"
    else
        printf '%s\n' "${absolute_path}"
    fi
}

find_latest_run_dir() {
    if [[ -L "${SBOM_ROOT}/latest" ]]; then
        printf -- '%s\n' "$(cd "${SBOM_ROOT}" && pwd)/$(readlink "${SBOM_ROOT}/latest")"
        return 0
    fi

    local latest_dir
    latest_dir="$(find "${SBOM_ROOT}" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
    [[ -n "${latest_dir}" ]] || return 1
    printf -- '%s\n' "${latest_dir}"
}

RUN_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-dir)
            [[ $# -ge 2 ]] || {
                usage >&2
                exit 2
            }
            RUN_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "${RUN_DIR}" ]]; then
    if ! RUN_DIR="$(find_latest_run_dir)"; then
        "${PROJECT_ROOT}/scripts/generate-sbom.sh"
        RUN_DIR="$(find_latest_run_dir)"
    fi
fi

RUN_DIR="$(cd "${RUN_DIR}" && pwd)"
METADATA_PATH="${RUN_DIR}/metadata.json"
VALIDATION_EVIDENCE_PATH="${RUN_DIR}/validation-evidence.json"

[[ -f "${METADATA_PATH}" ]] || {
    echo "Missing metadata file in ${RUN_DIR}" >&2
    exit 1
}
[[ -f "${VALIDATION_EVIDENCE_PATH}" ]] || {
    echo "Missing validation evidence file in ${RUN_DIR}" >&2
    exit 1
}

mkdir -p "${REPORT_ROOT}"

RUN_ID="$(jq -r '.run_id' "${METADATA_PATH}")"
REPORT_PATH="${REPORT_ROOT}/DSM-SBOM-${RUN_ID}.md"

GENERATED_AT="$(jq -r '.generated_at' "${METADATA_PATH}")"
COMMIT="$(jq -r '.git.commit' "${METADATA_PATH}")"
BRANCH="$(jq -r '.git.branch' "${METADATA_PATH}")"
TREE_STATE="$(jq -r '.git.tree_state' "${METADATA_PATH}")"
TOTAL_COMPONENTS="$(jq -r '.summary.total_components' "${METADATA_PATH}")"
RUST_COMPONENTS="$(jq -r '.summary.rust_components' "${METADATA_PATH}")"
NODE_RESOLVED_COMPONENTS="$(jq -r '.summary.node_resolved_components' "${METADATA_PATH}")"
NODE_MANIFEST_COMPONENTS="$(jq -r '.summary.node_manifest_components' "${METADATA_PATH}")"
ANDROID_COMPONENTS="$(jq -r '.summary.android_manifest_components' "${METADATA_PATH}")"
CONSOLIDATED_SBOM="$(jq -r '.artifacts.consolidated_sbom' "${METADATA_PATH}")"
VALIDATION_EVIDENCE="$(jq -r '.artifacts.validation_evidence' "${METADATA_PATH}")"
VALIDATION_LOG="$(jq -r '.artifacts.validation_log' "${METADATA_PATH}")"
VALIDATION_STATUS="$(jq -r '.status' "${VALIDATION_EVIDENCE_PATH}")"
VALIDATION_COMMAND="$(jq -r '.command' "${VALIDATION_EVIDENCE_PATH}")"

{
    printf -- '# DSM SBOM Report\n\n'
    printf -- '- Generated: `%s`\n' "${GENERATED_AT}"
    printf -- '- Run ID: `%s`\n' "${RUN_ID}"
    printf -- '- Commit: `%s`\n' "${COMMIT}"
    printf -- '- Branch: `%s`\n' "${BRANCH}"
    printf -- '- Tree State: `%s`\n\n' "${TREE_STATE}"

    printf -- '## What This Bundle Contains\n\n'
    printf -- '- A consolidated CycloneDX SBOM at `%s`\n' "${CONSOLIDATED_SBOM}"
    printf -- '- Per-ecosystem inventories under `%s`\n' "$(relative_path "${RUN_DIR}")"
    printf -- '- Validation evidence from the integrated TLA check at `%s`\n\n' "${VALIDATION_EVIDENCE}"

    printf -- '## Inventory Summary\n\n'
    printf -- '| Inventory | Resolution | Components |\n'
    printf -- '|---|---|---:|\n'
    printf -- '| Rust workspace | resolved via `cargo cyclonedx` | %s |\n' "${RUST_COMPONENTS}"
    printf -- '| Node lockfiles | resolved via `package-lock.json` | %s |\n' "${NODE_RESOLVED_COMPONENTS}"
    printf -- '| Root JS workspace | manifest snapshot | %s |\n' "${NODE_MANIFEST_COMPONENTS}"
    printf -- '| Android build files | manifest snapshot | %s |\n' "${ANDROID_COMPONENTS}"
    printf -- '| Consolidated total | merged unique components | %s |\n\n' "${TOTAL_COMPONENTS}"

    printf -- '## Validation Evidence\n\n'
    printf -- '- Status: `%s`\n' "${VALIDATION_STATUS}"
    printf -- '- Command: `%s`\n' "${VALIDATION_COMMAND}"
    printf -- '- Log: `%s`\n\n' "${VALIDATION_LOG}"

    if [[ "${VALIDATION_STATUS}" == "pass" || "${VALIDATION_STATUS}" == "fail" ]]; then
        printf -- 'Validation summary lines:\n\n'
        while IFS= read -r summary_line; do
            [[ -n "${summary_line}" ]] || continue
            printf -- '- `%s`\n' "${summary_line}"
        done < <(jq -r '.summary_lines[]?' "${VALIDATION_EVIDENCE_PATH}")
        printf -- '\n'
    fi

    printf -- '## Limits\n\n'
    while IFS= read -r limit_line; do
        printf -- '- %s\n' "${limit_line}"
    done < <(jq -r '.limits[]' "${METADATA_PATH}")
    printf -- '\n'

    printf -- '## Reproduce\n\n'
    printf -- '```bash\n'
    printf -- './scripts/generate-sbom.sh\n'
    printf -- './scripts/generate-sbom-report.sh --run-dir %s\n' "$(relative_path "${RUN_DIR}")"
    printf -- 'cargo run -p dsm_vertical_validation -- tla-check\n'
    printf -- '```\n'
} > "${REPORT_PATH}"

printf -- '%s\n' "${REPORT_PATH}"
