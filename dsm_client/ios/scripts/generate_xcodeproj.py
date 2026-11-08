#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Writes DsmWallet.xcodeproj/project.pbxproj from the files on disk.

The project is derived, not hand-edited: every Swift file under DsmWallet/ is
a source of the app, every Swift file under DsmWalletTests/ a source of the
test bundle, `www/` is packaged as a folder, `Web/bridge_bootstrap.js` as a
resource, and `Native/DsmSdk.xcframework` is linked. Object ids are the first
24 hex digits of a sha1 of each object's role and path, so a regeneration
changes only what changed. Run it after adding or removing a file:

    python3 dsm_client/ios/scripts/generate_xcodeproj.py
"""

import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = "DsmWallet"
TESTS = "DsmWalletTests"
BUNDLE_ID = "com.dsm.wallet"
DEPLOYMENT_TARGET = "17.0"


def oid(*parts):
    return hashlib.sha1("/".join(parts).encode()).hexdigest()[:24].upper()


def swift_files(folder):
    out = []
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, folder)):
        dirnames.sort()
        for name in sorted(filenames):
            if name.endswith(".swift"):
                out.append(os.path.relpath(os.path.join(dirpath, name), ROOT))
    return out


def quoted(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    app_sources = swift_files(APP)
    test_sources = swift_files(TESTS)
    if not app_sources:
        sys.exit("no Swift sources under DsmWallet/")

    objects = []

    def add(obj_id, body):
        objects.append((obj_id, body))

    # File references and build files.
    def file_ref(path, file_type, name=None, source_tree="<group>"):
        ref = oid("ref", path)
        name = name or os.path.basename(path)
        add(ref, f"{{isa = PBXFileReference; lastKnownFileType = {file_type}; name = {quoted(name)}; path = {quoted(path)}; sourceTree = {quoted(source_tree)}; }}")
        return ref

    def build_file(path, ref):
        bid = oid("build", path)
        add(bid, f"{{isa = PBXBuildFile; fileRef = {ref}; }}")
        return bid

    app_source_refs = [(p, file_ref(p, "sourcecode.swift")) for p in app_sources]
    test_source_refs = [(p, file_ref(p, "sourcecode.swift")) for p in test_sources]
    app_source_builds = [build_file(p, r) for p, r in app_source_refs]
    test_source_builds = [build_file(p, r) for p, r in test_source_refs]

    www_ref = file_ref(f"{APP}/www", "folder")
    bootstrap_ref = file_ref(f"{APP}/Web/bridge_bootstrap.js", "sourcecode.javascript")
    plist_ref = file_ref(f"{APP}/Info.plist", "text.plist.xml")
    resource_builds = [build_file(f"{APP}/www", www_ref), build_file(f"{APP}/Web/bridge_bootstrap.js", bootstrap_ref)]

    xcframework_ref = file_ref("Native/DsmSdk.xcframework", "wrapper.xcframework")
    framework_builds = [build_file("Native/DsmSdk.xcframework", xcframework_ref)]

    app_product = oid("product", APP)
    add(app_product, f"{{isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = {quoted(APP + '.app')}; sourceTree = BUILT_PRODUCTS_DIR; }}")
    test_product = oid("product", TESTS)
    add(test_product, f"{{isa = PBXFileReference; explicitFileType = wrapper.cfbundle; includeInIndex = 0; path = {quoted(TESTS + '.xctest')}; sourceTree = BUILT_PRODUCTS_DIR; }}")

    # Groups.
    def group(name, children, path=None):
        gid = oid("group", name)
        path_part = f" path = {quoted(path)};" if path else ""
        add(gid, f"{{isa = PBXGroup; children = ({', '.join(children)}); name = {quoted(name)};{path_part} sourceTree = {quoted('<group>')}; }}")
        return gid

    app_group = group(APP, [r for _, r in app_source_refs] + [www_ref, bootstrap_ref, plist_ref])
    test_group = group(TESTS, [r for _, r in test_source_refs])
    native_group = group("Native", [xcframework_ref])
    products_group = group("Products", [app_product, test_product])
    main_group = group("DsmWalletRoot", [app_group, test_group, native_group, products_group])

    # Build phases.
    def phase(kind, name, files):
        pid = oid("phase", kind, name)
        add(pid, f"{{isa = {kind}; buildActionMask = 2147483647; files = ({', '.join(files)}); runOnlyForDeploymentPostprocessing = 0; }}")
        return pid

    app_sources_phase = phase("PBXSourcesBuildPhase", APP, app_source_builds)
    app_resources_phase = phase("PBXResourcesBuildPhase", APP, resource_builds)
    app_frameworks_phase = phase("PBXFrameworksBuildPhase", APP, framework_builds)
    test_sources_phase = phase("PBXSourcesBuildPhase", TESTS, test_source_builds)
    test_frameworks_phase = phase("PBXFrameworksBuildPhase", TESTS, [])

    # The build refuses what scripts/real_code_guard.py forbids under dsm_client/ios.
    guard_phase = oid("phase", "guard", APP)
    guard_script = (
        'cd "$SRCROOT/../.." && python3 scripts/real_code_guard.py --scope dsm_client/ios'
    )
    add(guard_phase, "{isa = PBXShellScriptBuildPhase; alwaysOutOfDate = 1; buildActionMask = 2147483647; files = (); "
                     "inputPaths = (); name = \"Real-code guard\"; outputPaths = (); runOnlyForDeploymentPostprocessing = 0; "
                     f"shellPath = /bin/sh; shellScript = {quoted(guard_script + chr(10))}; }}")

    # Build configurations.
    def settings(entries):
        return "{" + " ".join(f"{k} = {v};" for k, v in entries) + "}"

    common_project = [
        ("ALWAYS_SEARCH_USER_PATHS", "NO"),
        ("CLANG_ENABLE_MODULES", "YES"),
        ("CLANG_ENABLE_OBJC_ARC", "YES"),
        ("ENABLE_STRICT_OBJC_MSGSEND", "YES"),
        ("GCC_NO_COMMON_BLOCKS", "YES"),
        ("IPHONEOS_DEPLOYMENT_TARGET", DEPLOYMENT_TARGET),
        ("SDKROOT", "iphoneos"),
        ("SWIFT_VERSION", "5.0"),
        ("TARGETED_DEVICE_FAMILY", quoted("1,2")),
        ("ENABLE_USER_SCRIPT_SANDBOXING", "NO"),
    ]
    debug_project = common_project + [
        ("DEBUG_INFORMATION_FORMAT", "dwarf"),
        ("ENABLE_TESTABILITY", "YES"),
        ("GCC_OPTIMIZATION_LEVEL", "0"),
        ("GCC_PREPROCESSOR_DEFINITIONS", quoted("DEBUG=1 $(inherited)")),
        ("ONLY_ACTIVE_ARCH", "YES"),
        ("SWIFT_ACTIVE_COMPILATION_CONDITIONS", "DEBUG"),
        ("SWIFT_OPTIMIZATION_LEVEL", quoted("-Onone")),
    ]
    release_project = common_project + [
        ("DEBUG_INFORMATION_FORMAT", quoted("dwarf-with-dsym")),
        ("ENABLE_NS_ASSERTIONS", "NO"),
        ("SWIFT_COMPILATION_MODE", "wholemodule"),
        ("SWIFT_OPTIMIZATION_LEVEL", quoted("-O")),
        ("VALIDATE_PRODUCT", "YES"),
    ]
    app_settings = [
        ("ASSETCATALOG_COMPILER_APPICON_NAME", "AppIcon"),
        ("CODE_SIGN_STYLE", "Automatic"),
        ("CURRENT_PROJECT_VERSION", "1"),
        # One executable, not Xcode's debug stub plus dylib: the simulator's
        # Keychain reads the entitlements section of the executable that
        # calls it, and the seed vault's seal failed (-34018) under the split.
        ("ENABLE_DEBUG_DYLIB", "NO"),
        ("GENERATE_INFOPLIST_FILE", "NO"),
        ("INFOPLIST_FILE", quoted(f"{APP}/Info.plist")),
        ("LD_RUNPATH_SEARCH_PATHS", quoted("$(inherited) @executable_path/Frameworks")),
        ("MARKETING_VERSION", quoted("0.1.0-beta.4")),
        ("OTHER_LDFLAGS", quoted("$(inherited) -lresolv")),
        ("PRODUCT_BUNDLE_IDENTIFIER", BUNDLE_ID),
        ("PRODUCT_NAME", quoted("$(TARGET_NAME)")),
        ("SWIFT_EMIT_LOC_STRINGS", "YES"),
    ]
    test_settings = [
        ("BUNDLE_LOADER", quoted("$(TEST_HOST)")),
        ("CODE_SIGN_STYLE", "Automatic"),
        ("GENERATE_INFOPLIST_FILE", "YES"),
        ("PRODUCT_BUNDLE_IDENTIFIER", BUNDLE_ID + ".tests"),
        ("PRODUCT_NAME", quoted("$(TARGET_NAME)")),
        ("TEST_HOST", quoted(f"$(BUILT_PRODUCTS_DIR)/{APP}.app/$(BUNDLE_EXECUTABLE_FOLDER_PATH)/{APP}")),
    ]

    def configuration(name, owner, entries):
        cid = oid("config", owner, name)
        add(cid, f"{{isa = XCBuildConfiguration; buildSettings = {settings(entries)}; name = {name}; }}")
        return cid

    def configuration_list(owner, debug, release):
        lid = oid("configlist", owner)
        add(lid, f"{{isa = XCConfigurationList; buildConfigurations = ({debug}, {release}); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; }}")
        return lid

    project_configs = configuration_list("project", configuration("Debug", "project", debug_project), configuration("Release", "project", release_project))
    app_configs = configuration_list(APP, configuration("Debug", APP, app_settings), configuration("Release", APP, app_settings))
    test_configs = configuration_list(TESTS, configuration("Debug", TESTS, test_settings), configuration("Release", TESTS, test_settings))

    # Targets.
    app_target = oid("target", APP)
    test_target = oid("target", TESTS)
    dependency_proxy = oid("proxy", TESTS)
    dependency = oid("dependency", TESTS)
    project_id = oid("project")
    add(dependency_proxy, f"{{isa = PBXContainerItemProxy; containerPortal = {project_id}; proxyType = 1; remoteGlobalIDString = {app_target}; remoteInfo = {APP}; }}")
    add(dependency, f"{{isa = PBXTargetDependency; target = {app_target}; targetProxy = {dependency_proxy}; }}")
    add(app_target, f"{{isa = PBXNativeTarget; buildConfigurationList = {app_configs}; buildPhases = ({app_sources_phase}, {app_frameworks_phase}, {app_resources_phase}, {guard_phase}); "
                    f"buildRules = (); dependencies = (); name = {APP}; productName = {APP}; productReference = {app_product}; productType = {quoted('com.apple.product-type.application')}; }}")
    add(test_target, f"{{isa = PBXNativeTarget; buildConfigurationList = {test_configs}; buildPhases = ({test_sources_phase}, {test_frameworks_phase}); "
                     f"buildRules = (); dependencies = ({dependency}); name = {TESTS}; productName = {TESTS}; productReference = {test_product}; productType = {quoted('com.apple.product-type.bundle.unit-test')}; }}")

    add(project_id, f"{{isa = PBXProject; attributes = {{BuildIndependentTargetsInParallel = 1; LastUpgradeCheck = 2600; "
                    f"TargetAttributes = {{{app_target} = {{CreatedOnToolsVersion = 26.0;}}; {test_target} = {{CreatedOnToolsVersion = 26.0; TestTargetID = {app_target};}};}};}}; "
                    f"buildConfigurationList = {project_configs}; compatibilityVersion = {quoted('Xcode 14.0')}; developmentRegion = en; hasScannedForEncodings = 0; "
                    f"knownRegions = (en, Base); mainGroup = {main_group}; productRefGroup = {products_group}; projectDirPath = \"\"; projectRoot = \"\"; targets = ({app_target}, {test_target}); }}")

    lines = ["// !$*UTF8*$!", "{", "\tarchiveVersion = 1;", "\tclasses = {", "\t};", "\tobjectVersion = 56;", "\tobjects = {"]
    for obj_id, body in sorted(objects):
        lines.append(f"\t\t{obj_id} = {body};")
    lines += ["\t};", f"\trootObject = {project_id};", "}", ""]

    out_dir = os.path.join(ROOT, f"{APP}.xcodeproj")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "project.pbxproj"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"wrote {out_dir}/project.pbxproj: {len(app_sources)} app sources, {len(test_sources)} test sources")


if __name__ == "__main__":
    main()
