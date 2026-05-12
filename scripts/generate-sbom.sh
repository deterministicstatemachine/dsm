#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SBOM_ROOT="${PROJECT_ROOT}/sbom"
REPORT_ROOT="${PROJECT_ROOT}/reports"

usage() {
    cat <<'EOF'
Usage: scripts/generate-sbom.sh [--run-id <id>] [--skip-validation]

Generates a usable DSM SBOM bundle:
- Rust SBOMs from cargo-cyclonedx
- lockfile-resolved Node inventories where package-lock.json exists
- manifest snapshot inventories for the root npm workspace and Android Gradle files
- validation evidence from `cargo run -p dsm_vertical_validation -- tla-check`
EOF
}

require_command() {
    local command_name="$1"
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "Missing required command: ${command_name}" >&2
        exit 1
    fi
}

log() {
    printf '[sbom] %s\n' "$1"
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

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
SKIP_VALIDATION=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-id)
            [[ $# -ge 2 ]] || {
                usage >&2
                exit 2
            }
            RUN_ID="$2"
            shift 2
            ;;
        --skip-validation)
            SKIP_VALIDATION=1
            shift
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

require_command jq
require_command cargo
require_command git
if ! cargo cyclonedx --version >/dev/null 2>&1; then
    echo "Missing cargo-cyclonedx. Install with: cargo install cargo-cyclonedx" >&2
    exit 1
fi

RUN_DIR="${SBOM_ROOT}/${RUN_ID}"
RUST_DIR="${RUN_DIR}/rust"
RUST_CRATE_DIR="${RUST_DIR}/crates"
NODE_DIR="${RUN_DIR}/node"
ANDROID_DIR="${RUN_DIR}/android"
LOG_DIR="${RUN_DIR}/logs"
TMP_DIR="${RUN_DIR}/tmp"

mkdir -p "${RUST_CRATE_DIR}" "${NODE_DIR}" "${ANDROID_DIR}" "${LOG_DIR}" "${TMP_DIR}" "${REPORT_ROOT}"

GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_COMMIT="$(git -C "${PROJECT_ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"
GIT_BRANCH="$(git -C "${PROJECT_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || printf 'unknown')"
if [[ -n "$(git -C "${PROJECT_ROOT}" status --porcelain 2>/dev/null)" ]]; then
    GIT_TREE_STATE="dirty"
else
    GIT_TREE_STATE="clean"
fi

FRONTEND_LOCKFILE="${PROJECT_ROOT}/dsm_client/frontend/package-lock.json"
MCP_PACKAGE="${PROJECT_ROOT}/dsm-mcp/packages/server/package.json"
MCP_LOCKFILE="${PROJECT_ROOT}/dsm-mcp/packages/server/package-lock.json"
WORKSPACE_PACKAGE="${PROJECT_ROOT}/package.json"
ANDROID_ROOT_BUILD="${PROJECT_ROOT}/dsm_client/android/build.gradle.kts"
ANDROID_APP_BUILD="${PROJECT_ROOT}/dsm_client/android/app/build.gradle.kts"

RUST_METADATA_PATH="${TMP_DIR}/cargo-metadata.json"
RUST_SBOM_PATH="${RUST_DIR}/dsm-rust-resolved.cdx.json"
FRONTEND_SBOM_PATH="${NODE_DIR}/frontend-resolved.cdx.json"
MCP_SBOM_PATH="${NODE_DIR}/mcp-server-resolved.cdx.json"
WORKSPACE_MANIFEST_SBOM_PATH="${NODE_DIR}/workspace-manifest.cdx.json"
ANDROID_SBOM_PATH="${ANDROID_DIR}/android-manifest.cdx.json"
ANDROID_DEPENDENCIES_TSV="${TMP_DIR}/android-dependencies.tsv"
CONSOLIDATED_SBOM_PATH="${RUN_DIR}/dsm-consolidated.cdx.json"
VALIDATION_LOG_PATH="${LOG_DIR}/tla-check.log"
VALIDATION_EVIDENCE_PATH="${RUN_DIR}/validation-evidence.json"
METADATA_PATH="${RUN_DIR}/metadata.json"

generate_rust_sboms() {
    log "Collecting Rust workspace metadata"
    cargo metadata --format-version 1 --no-deps > "${RUST_METADATA_PATH}"

    while IFS=$'\t' read -r package_name manifest_path; do
        local override_name
        local generated_path_json
        local generated_path_cdx
        override_name="dsm-${package_name}-${RUN_ID}"
        generated_path_json="$(dirname "${manifest_path}")/${override_name}.json"
        generated_path_cdx="$(dirname "${manifest_path}")/${override_name}.cdx.json"

        log "Generating Rust SBOM for ${package_name}"
        rm -f "${generated_path_json}" "${generated_path_cdx}"
        cargo cyclonedx \
            --manifest-path "${manifest_path}" \
            --format json \
            --spec-version 1.5 \
            --override-filename "${override_name}" \
            >/dev/null
        if [[ -f "${generated_path_json}" ]]; then
            mv -f "${generated_path_json}" "${RUST_CRATE_DIR}/${package_name}.cdx.json"
        elif [[ -f "${generated_path_cdx}" ]]; then
            mv -f "${generated_path_cdx}" "${RUST_CRATE_DIR}/${package_name}.cdx.json"
        else
            echo "Unable to locate cargo-cyclonedx output for ${package_name}" >&2
            exit 1
        fi
    done < <(
        jq -r '
            . as $meta
            | $meta.packages[]
            | select(.id as $id | ($meta.workspace_members | index($id)))
            | [.name, .manifest_path]
            | @tsv
        ' "${RUST_METADATA_PATH}"
    )

    jq -s \
        --arg timestamp "${GENERATED_AT}" \
        --arg commit "${GIT_COMMIT}" \
        --arg branch "${GIT_BRANCH}" \
        --arg tree_state "${GIT_TREE_STATE}" \
        '
        reduce .[] as $doc (
            {
                bomFormat: "CycloneDX",
                specVersion: "1.5",
                version: 1,
                metadata: {
                    timestamp: $timestamp,
                    component: {
                        type: "platform",
                        name: "dsm-rust-workspace",
                        version: $commit,
                        properties: [
                            { name: "dsm.git.commit", value: $commit },
                            { name: "dsm.git.branch", value: $branch },
                            { name: "dsm.git.tree_state", value: $tree_state },
                            { name: "dsm.inventory.kind", value: "resolved" },
                            { name: "dsm.inventory.source", value: "cargo-cyclonedx" }
                        ]
                    }
                },
                components: [],
                dependencies: []
            };
            .components += ($doc.components // [])
            | .dependencies += ($doc.dependencies // [])
        )
        | .components |= unique_by(."bom-ref" // (.name + "@" + (.version // "")))
        | .dependencies |= unique_by(.ref)
        ' "${RUST_CRATE_DIR}"/*.cdx.json > "${RUST_SBOM_PATH}"
}

generate_node_lockfile_sbom() {
    local lockfile_path="$1"
    local output_path="$2"
    local component_name="$3"
    local component_version="$4"

    local manifest_path lockfile_rel manifest_rel
    manifest_path="$(dirname "${lockfile_path}")/package.json"
    lockfile_rel="$(relative_path "${lockfile_path}")"
    manifest_rel="$(relative_path "${manifest_path}")"

    jq -n \
        --arg timestamp "${GENERATED_AT}" \
        --arg component_name "${component_name}" \
        --arg component_version "${component_version}" \
        --arg manifest_path "${manifest_rel}" \
        --arg lockfile_path "${lockfile_rel}" \
        '
        def ref_from_name($name; $version):
            "npm:" + $name + "@" + ($version // "unknown");
        def package_name($key; $value):
            if $key == "" then ($value.name // $component_name)
            else ($value.name // ($key | split("node_modules/") | last))
            end;
        def licenses_from($value):
            if $value == null then []
            elif ($value | type) == "string" then
                [{ license: { name: $value } }]
            elif ($value | type) == "array" then
                $value | map(
                    if type == "string" then
                        { license: { name: . } }
                    else
                        { license: { name: (tostring) } }
                    end
                )
            else
                [{ license: { name: ($value | tostring) } }]
            end;
        (input) as $lock
        | ($lock.packages // {}) as $packages
        | {
            bomFormat: "CycloneDX",
            specVersion: "1.5",
            version: 1,
            metadata: {
                timestamp: $timestamp,
                component: {
                    type: "application",
                    "bom-ref": ref_from_name($component_name; $component_version),
                    name: $component_name,
                    version: $component_version,
                    properties: [
                        { name: "dsm.inventory.kind", value: "resolved" },
                        { name: "dsm.inventory.source", value: "package-lock.json" },
                        { name: "dsm.source.manifest", value: $manifest_path },
                        { name: "dsm.source.lockfile", value: $lockfile_path }
                    ]
                }
            },
            components: (
                $packages
                | to_entries
                | map(select(.key != ""))
                | map(
                    (package_name(.key; .value)) as $pkg_name
                    | (.value.version // "unknown") as $pkg_version
                    | {
                        type: "library",
                        "bom-ref": ref_from_name($pkg_name; $pkg_version),
                        name: $pkg_name,
                        version: $pkg_version,
                        scope: (if .value.dev == true then "excluded" else "required" end),
                        licenses: licenses_from(.value.license),
                        properties: (
                            [
                                { name: "dsm.source.lockfile", value: $lockfile_path },
                                { name: "dsm.source.package_path", value: .key }
                            ]
                            + (if .value.resolved? then [{ name: "dsm.npm.resolved", value: .value.resolved }] else [] end)
                            + (if .value.integrity? then [{ name: "dsm.npm.integrity", value: .value.integrity }] else [] end)
                        )
                    }
                )
            ),
            dependencies: [
                {
                    ref: ref_from_name($component_name; $component_version),
                    dependsOn: (
                        (($packages[""].dependencies // {}) + ($packages[""].devDependencies // {}))
                        | keys
                        | map(
                            . as $dep_name
                            | ($packages["node_modules/" + $dep_name] // {}) as $resolved
                            | select(($resolved.version // null) != null)
                            | ref_from_name(($resolved.name // $dep_name); $resolved.version)
                        )
                    )
                }
            ]
        }
        ' "${lockfile_path}" > "${output_path}"
}

generate_workspace_manifest_sbom() {
    local manifest_rel
    manifest_rel="$(relative_path "${WORKSPACE_PACKAGE}")"

    jq -n \
        --arg timestamp "${GENERATED_AT}" \
        --arg manifest_path "${manifest_rel}" \
        '
        def manifest_components($deps; $scope):
            ($deps // {})
            | to_entries
            | map({
                type: "library",
                "bom-ref": ("manifest:" + .key + "@" + (.value | tostring)),
                name: .key,
                version: (.value | tostring),
                scope: $scope,
                properties: [
                    { name: "dsm.inventory.kind", value: "manifest-snapshot" },
                    { name: "dsm.manifest_only", value: "true" },
                    { name: "dsm.source.manifest", value: $manifest_path }
                ]
            });
        (input) as $pkg
        | {
            bomFormat: "CycloneDX",
            specVersion: "1.5",
            version: 1,
            metadata: {
                timestamp: $timestamp,
                component: {
                    type: "application",
                    "bom-ref": ("manifest-root:" + $pkg.name + "@" + ($pkg.version // "0.0.0")),
                    name: $pkg.name,
                    version: ($pkg.version // "0.0.0"),
                    properties: [
                        { name: "dsm.inventory.kind", value: "manifest-snapshot" },
                        { name: "dsm.inventory.source", value: "package.json" },
                        { name: "dsm.source.manifest", value: $manifest_path },
                        { name: "dsm.note", value: "Root JS workspace is captured from package.json and package-lock.json." }
                    ]
                }
            },
            components: (
                manifest_components($pkg.dependencies; "required")
                + manifest_components($pkg.devDependencies; "excluded")
            )
        }
        ' "${WORKSPACE_PACKAGE}" > "${WORKSPACE_MANIFEST_SBOM_PATH}"
}

generate_placeholder_sbom() {
    local output_path="$1"
    local component_name="$2"
    local component_version="$3"
    local note="$4"

    jq -n \
        --arg timestamp "${GENERATED_AT}" \
        --arg component_name "${component_name}" \
        --arg component_version "${component_version}" \
        --arg note "${note}" \
        '
        {
            bomFormat: "CycloneDX",
            specVersion: "1.5",
            version: 1,
            metadata: {
                timestamp: $timestamp,
                component: {
                    type: "application",
                    "bom-ref": ("placeholder:" + $component_name + "@" + $component_version),
                    name: $component_name,
                    version: $component_version,
                    properties: [
                        { name: "dsm.inventory.kind", value: "placeholder" },
                        { name: "dsm.inventory.source", value: "optional-workspace-absent" },
                        { name: "dsm.note", value: $note }
                    ]
                }
            },
            components: [],
            dependencies: []
        }
        ' > "${output_path}"
}

declare -A GRADLE_VARS=()

collect_gradle_vars() {
    local gradle_file="$1"
    while IFS= read -r line; do
        if [[ "${line}" =~ ^[[:space:]]*val[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*\"([^\"]+)\" ]]; then
            GRADLE_VARS["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
        fi
    done < "${gradle_file}"
}

substitute_gradle_vars() {
    local text="$1"
    local variable_name
    for variable_name in "${!GRADLE_VARS[@]}"; do
        text="${text//\$\{${variable_name}\}/${GRADLE_VARS[${variable_name}]}}"
        text="${text//\$${variable_name}/${GRADLE_VARS[${variable_name}]}}"
    done
    printf '%s\n' "${text}"
}

extract_gradle_dependencies() {
    local gradle_file="$1"
    local relative_file
    relative_file="$(relative_path "${gradle_file}")"

    while IFS= read -r line; do
        if [[ "${line}" =~ ^[[:space:]]*(classpath|implementation|debugImplementation|testImplementation|androidTestImplementation)[[:space:]]*\((platform\()?\"([^\"]+)\" ]]; then
            local configuration platform_marker coordinate resolved_coordinate group_id artifact_id version
            configuration="${BASH_REMATCH[1]}"
            platform_marker="${BASH_REMATCH[2]:-}"
            coordinate="${BASH_REMATCH[3]}"
            resolved_coordinate="$(substitute_gradle_vars "${coordinate}")"

            IFS=':' read -r group_id artifact_id version _ <<< "${resolved_coordinate}"
            if [[ -z "${group_id:-}" || -z "${artifact_id:-}" ]]; then
                continue
            fi

            printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
                "${configuration}" \
                "${group_id}" \
                "${artifact_id}" \
                "${version:-}" \
                "$([[ -n "${platform_marker}" ]] && printf 'true' || printf 'false')" \
                "${relative_file}"
        fi
    done < "${gradle_file}"
}

generate_android_manifest_sbom() {
    log "Collecting Android manifest dependencies"
    : > "${ANDROID_DEPENDENCIES_TSV}"
    collect_gradle_vars "${ANDROID_ROOT_BUILD}"
    collect_gradle_vars "${ANDROID_APP_BUILD}"
    extract_gradle_dependencies "${ANDROID_ROOT_BUILD}" >> "${ANDROID_DEPENDENCIES_TSV}"
    extract_gradle_dependencies "${ANDROID_APP_BUILD}" >> "${ANDROID_DEPENDENCIES_TSV}"

    jq -Rn \
        --arg timestamp "${GENERATED_AT}" \
        --arg android_root_build "$(relative_path "${ANDROID_ROOT_BUILD}")" \
        --arg android_app_build "$(relative_path "${ANDROID_APP_BUILD}")" \
        '
        def row_to_dependency:
            split("\t") as $row
            | {
                configuration: $row[0],
                group: $row[1],
                artifact: $row[2],
                version: ($row[3] // ""),
                is_platform: ($row[4] == "true"),
                source: $row[5]
            };
        [inputs | select(length > 0) | row_to_dependency] as $rows
        | {
            bomFormat: "CycloneDX",
            specVersion: "1.5",
            version: 1,
            metadata: {
                timestamp: $timestamp,
                component: {
                    type: "application",
                    "bom-ref": "android:dsm-android-manifest",
                    name: "dsm-android",
                    version: "manifest-snapshot",
                    properties: [
                        { name: "dsm.inventory.kind", value: "manifest-snapshot" },
                        { name: "dsm.inventory.source", value: "Gradle build files" },
                        { name: "dsm.source.manifest", value: $android_root_build },
                        { name: "dsm.source.manifest", value: $android_app_build },
                        { name: "dsm.note", value: "Android dependencies are build-file derived in this run; they are not Gradle-resolved." }
                    ]
                }
            },
            components: (
                $rows
                | map({
                    type: "library",
                    "bom-ref": (
                        "maven:" + .group + ":" + .artifact + ":" +
                        (if (.version | length) > 0 then .version else "unresolved" end)
                    ),
                    group: .group,
                    name: .artifact,
                    version: (if (.version | length) > 0 then .version else "unresolved" end),
                    scope: (
                        if (.configuration | test("test|androidTest|debug")) then
                            "excluded"
                        else
                            "required"
                        end
                    ),
                    properties: (
                        [
                            { name: "dsm.source.manifest", value: .source },
                            { name: "dsm.android.configuration", value: .configuration }
                        ]
                        + (if .is_platform then [{ name: "dsm.android.platform_bom", value: "true" }] else [] end)
                        + (if (.version | length) == 0 then [{ name: "dsm.android.version_source", value: "managed externally or omitted in build file" }] else [] end)
                    )
                })
                | unique_by(."bom-ref")
            )
        }
        ' < "${ANDROID_DEPENDENCIES_TSV}" > "${ANDROID_SBOM_PATH}"
}

generate_consolidated_sbom() {
    log "Writing consolidated SBOM"
    jq -s \
        --arg timestamp "${GENERATED_AT}" \
        --arg commit "${GIT_COMMIT}" \
        --arg branch "${GIT_BRANCH}" \
        --arg tree_state "${GIT_TREE_STATE}" \
        --arg validation_path "$(relative_path "${VALIDATION_EVIDENCE_PATH}")" \
        '
        reduce .[] as $doc (
            {
                bomFormat: "CycloneDX",
                specVersion: "1.5",
                version: 1,
                metadata: {
                    timestamp: $timestamp,
                    component: {
                        type: "platform",
                        name: "dsm-workspace",
                        version: $commit,
                        properties: [
                            { name: "dsm.git.commit", value: $commit },
                            { name: "dsm.git.branch", value: $branch },
                            { name: "dsm.git.tree_state", value: $tree_state },
                            { name: "dsm.validation.evidence", value: $validation_path }
                        ]
                    }
                },
                components: [],
                dependencies: []
            };
            .components += ($doc.components // [])
            | .dependencies += ($doc.dependencies // [])
        )
        | .components |= unique_by(."bom-ref" // (.name + "@" + (.version // "")))
        | .dependencies |= unique_by(.ref)
        ' \
        "${RUST_SBOM_PATH}" \
        "${FRONTEND_SBOM_PATH}" \
        "${MCP_SBOM_PATH}" \
        "${WORKSPACE_MANIFEST_SBOM_PATH}" \
        "${ANDROID_SBOM_PATH}" > "${CONSOLIDATED_SBOM_PATH}"
}

generate_validation_evidence() {
    local validation_status validation_exit_code summary_lines_json

    if [[ "${SKIP_VALIDATION}" -eq 1 ]]; then
        validation_status="skipped"
        validation_exit_code=0
        : > "${VALIDATION_LOG_PATH}"
    else
        log "Running integrated TLA validation"
        set +e
        cargo run -p dsm_vertical_validation -- tla-check > "${VALIDATION_LOG_PATH}" 2>&1
        validation_exit_code=$?
        set -e
        if [[ "${validation_exit_code}" -eq 0 ]]; then
            validation_status="pass"
        else
            validation_status="fail"
        fi
    fi

    summary_lines_json="$(
        jq -Rn '
            [inputs | select(test("DSM_(tiny|small|system)|Tripwire"))]
        ' < "${VALIDATION_LOG_PATH}"
    )"

    jq -n \
        --arg generated_at "${GENERATED_AT}" \
        --arg status "${validation_status}" \
        --arg command "cargo run -p dsm_vertical_validation -- tla-check" \
        --arg log_path "$(relative_path "${VALIDATION_LOG_PATH}")" \
        --argjson exit_code "${validation_exit_code}" \
        --argjson summary_lines "${summary_lines_json}" \
        '
        {
            generated_at: $generated_at,
            status: $status,
            exit_code: $exit_code,
            command: $command,
            log_path: $log_path,
            summary_lines: $summary_lines
        }
        ' > "${VALIDATION_EVIDENCE_PATH}"

    return "${validation_exit_code}"
}

generate_metadata() {
    local rust_workspace_members rust_components frontend_components mcp_components workspace_manifest_components android_components total_components mcp_lockfile_rel
    rust_workspace_members="$(jq '.workspace_members | length' "${RUST_METADATA_PATH}")"
    rust_components="$(jq '.components | length' "${RUST_SBOM_PATH}")"
    frontend_components="$(jq '.components | length' "${FRONTEND_SBOM_PATH}")"
    mcp_components="$(jq '.components | length' "${MCP_SBOM_PATH}")"
    workspace_manifest_components="$(jq '.components | length' "${WORKSPACE_MANIFEST_SBOM_PATH}")"
    android_components="$(jq '.components | length' "${ANDROID_SBOM_PATH}")"
    total_components="$(jq '.components | length' "${CONSOLIDATED_SBOM_PATH}")"
    if [[ -f "${MCP_LOCKFILE}" ]]; then
        mcp_lockfile_rel="$(relative_path "${MCP_LOCKFILE}")"
    else
        mcp_lockfile_rel=""
    fi

    jq -n \
        --arg run_id "${RUN_ID}" \
        --arg generated_at "${GENERATED_AT}" \
        --arg project_root "$(relative_path "${PROJECT_ROOT}")" \
        --arg commit "${GIT_COMMIT}" \
        --arg branch "${GIT_BRANCH}" \
        --arg tree_state "${GIT_TREE_STATE}" \
        --arg consolidated_sbom "$(relative_path "${CONSOLIDATED_SBOM_PATH}")" \
        --arg rust_dir "$(relative_path "${RUST_DIR}")" \
        --arg node_dir "$(relative_path "${NODE_DIR}")" \
        --arg android_dir "$(relative_path "${ANDROID_DIR}")" \
        --arg validation_evidence "$(relative_path "${VALIDATION_EVIDENCE_PATH}")" \
        --arg validation_log "$(relative_path "${VALIDATION_LOG_PATH}")" \
        --arg rust_metadata "$(relative_path "${RUST_METADATA_PATH}")" \
        --arg frontend_lockfile "$(relative_path "${FRONTEND_LOCKFILE}")" \
        --arg mcp_lockfile "${mcp_lockfile_rel}" \
        --arg workspace_manifest "$(relative_path "${WORKSPACE_PACKAGE}")" \
        --arg android_root_build "$(relative_path "${ANDROID_ROOT_BUILD}")" \
        --arg android_app_build "$(relative_path "${ANDROID_APP_BUILD}")" \
        --argjson rust_workspace_members "${rust_workspace_members}" \
        --argjson rust_components "${rust_components}" \
        --argjson frontend_components "${frontend_components}" \
        --argjson mcp_components "${mcp_components}" \
        --argjson workspace_manifest_components "${workspace_manifest_components}" \
        --argjson android_components "${android_components}" \
        --argjson total_components "${total_components}" \
        '
        {
            run_id: $run_id,
            generated_at: $generated_at,
            project_root: $project_root,
            git: {
                commit: $commit,
                branch: $branch,
                tree_state: $tree_state
            },
            artifacts: {
                consolidated_sbom: $consolidated_sbom,
                rust_dir: $rust_dir,
                node_dir: $node_dir,
                android_dir: $android_dir,
                validation_evidence: $validation_evidence,
                validation_log: $validation_log
            },
            inputs: {
                rust_workspace_members: $rust_workspace_members,
                rust_metadata: $rust_metadata,
                frontend_lockfile: $frontend_lockfile,
                mcp_lockfile: $mcp_lockfile,
                workspace_manifest: $workspace_manifest,
                android_manifests: [$android_root_build, $android_app_build]
            },
            summary: {
                total_components: $total_components,
                rust_components: $rust_components,
                node_resolved_components: ($frontend_components + $mcp_components),
                node_manifest_components: $workspace_manifest_components,
                android_manifest_components: $android_components
            },
            limits: [
                "Rust dependencies are resolved through cargo-cyclonedx for the current host target and current feature set.",
                "Frontend and optional MCP server Node inventories are lockfile-resolved where package-lock.json is present.",
                "The root JS workspace inventory is lockfile-resolved via package-lock.json.",
                "Android dependencies are build-file derived in this run; they are not Gradle-resolved.",
                "No vulnerability scan or license/compliance verdict is included by this generator."
            ]
        }
        ' > "${METADATA_PATH}"
}

main() {
    local validation_exit_code
    validation_exit_code=0

    generate_rust_sboms
    generate_node_lockfile_sbom "${FRONTEND_LOCKFILE}" "${FRONTEND_SBOM_PATH}" "dsm-wallet" "$(jq -r '.version // "0.0.0"' "${PROJECT_ROOT}/dsm_client/frontend/package.json")"
    if [[ -f "${MCP_LOCKFILE}" && -f "${MCP_PACKAGE}" ]]; then
        generate_node_lockfile_sbom "${MCP_LOCKFILE}" "${MCP_SBOM_PATH}" "@dsm/mcp-server" "$(jq -r '.version // "0.0.0"' "${MCP_PACKAGE}")"
    else
        log "Skipping optional MCP inventory; dsm-mcp workspace is not present"
        generate_placeholder_sbom "${MCP_SBOM_PATH}" "@dsm/mcp-server" "0.0.0" "Optional MCP workspace not present in this checkout"
    fi
    generate_workspace_manifest_sbom
    generate_android_manifest_sbom
    generate_consolidated_sbom
    if generate_validation_evidence; then
        :
    else
        validation_exit_code=$?
    fi
    generate_metadata

    ln -sfn "${RUN_ID}" "${SBOM_ROOT}/latest"

    "${SCRIPT_DIR}/generate-sbom-report.sh" --run-dir "${RUN_DIR}" >/dev/null

    log "SBOM bundle ready at $(relative_path "${RUN_DIR}")"
    log "Consolidated SBOM: $(relative_path "${CONSOLIDATED_SBOM_PATH}")"
    log "Validation evidence: $(relative_path "${VALIDATION_EVIDENCE_PATH}")"

    return "${validation_exit_code}"
}

main
