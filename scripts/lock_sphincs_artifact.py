#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fail-closed, local build identity inventory. This is not a semantic proof."""
import argparse
import sys
import hashlib
import os
import pathlib
import re
import shlex
import subprocess
if sys.version_info < (3, 11):
    raise SystemExit("Artifact locking requires Python 3.11 or later (tomllib)")
import tomllib


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def quote(text):
    return '"' + str(text).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'


def check(manifest):
    data = tomllib.loads(manifest.read_text())
    inventory = pathlib.Path(data['inventory'])
    if sha(inventory) != data['inventory_sha256']:
        raise SystemExit('Artifact inventory changed')
    rows = inventory.read_text().splitlines()[1:]
    for row in rows:
        digest, path = row.split('\t', 1)
        path = pathlib.Path(path)
        if not path.is_file() or sha(path) != digest:
            raise SystemExit(f'Artifact identity mismatch: {path}')
    print(f'Identity checked: {len(rows)} files. Runtime semantics and device libraries remain unproved/unlocked.')


def lock(args):
    repo = pathlib.Path(__file__).resolve().parent.parent
    out = args.out.resolve()
    ndk = args.ndk.resolve()
    build_log = args.build_log.resolve()
    text = build_log.read_text()
    if 'Finished `release` profile' not in text:
        raise SystemExit('A completed release build log is required')
    invocation = [line for line in text.splitlines() if 'Running `' in line and
                  '--crate-name dsm_sdk ' in line]
    if len(invocation) != 1:
        raise SystemExit('Expected exactly one recorded SDK rustc invocation')
    flags = invocation[0].split('Running `', 1)[1].removesuffix('`')
    for token in ['--target aarch64-linux-android', '-C opt-level=3', '-C overflow-checks=on',
                  '-C embed-bitcode=no', '--emit=asm,llvm-ir,link']:
        if token not in flags:
            raise SystemExit(f'Unexpected build profile: missing {token}')
    # Explicit flags override these defaults and must be reflected before locking.
    for pattern in [r'-C\s+panic=', r'-C\s+lto=', r'-C\s+codegen-units=']:
        if re.search(pattern, flags):
            raise SystemExit('Profile overrides require updating the identity recorder')
    sdk = repo/'target/aarch64-linux-android/release'
    tool = ndk/'toolchains/llvm/prebuilt/darwin-x86_64/bin'
    sysroot = pathlib.Path(command('rustc', '--print', 'sysroot'))
    target_lib = pathlib.Path(command('rustc', '--print', 'target-libdir', '--target', 'aarch64-linux-android'))
    files = set()
    def add(path):
        path = pathlib.Path(path).resolve()
        if path.is_dir():
            files.update(p.resolve() for p in path.rglob('*') if p.is_file())
        elif path.is_file():
            files.add(path)
        else:
            raise SystemExit(f'Missing build input: {path}')
    changed = command('git','-C',str(repo),'diff','--name-only').splitlines()
    if any(p.endswith(('.rs','.proto','.c','.h','.S','Cargo.toml','Cargo.lock')) or '.cargo/' in p for p in changed):
        raise SystemExit('Commit source/build-input edits before locking an artifact')
    for name in ['Cargo.lock','Cargo.toml']:
        add(repo/name)
    add(build_log)
    for directory in [repo,*repo.parents,pathlib.Path.home()/'.cargo']:
        for name in ['.cargo/config.toml','.cargo/config'] if directory != pathlib.Path.home()/'.cargo' else ['config.toml','config']:
            candidate = directory/name
            if candidate.is_file():
                add(candidate)
    for p in repo.rglob('Cargo.toml'):
        if 'target' not in p.relative_to(repo).parts and '.git' not in p.parts:
            add(p)
    # Cargo's complete top-level dep-info includes transitive Rust/path inputs,
    # generated files, build scripts and protobuf include directories.
    depfile = sdk/'libdsm_sdk.d'
    add(depfile)
    for line in depfile.read_text().splitlines():
        if ': ' in line:
            for path in shlex.split(line.split(': ', 1)[1]):
                add(path)
    for pattern in ['deps/*.rlib','deps/*.rmeta','build/**/out/*.a','build/**/out/**/*.rs']:
        for p in sdk.glob(pattern):
            add(p)
    for name in ['libdsm_sdk.so','deps/dsm_sdk.ll','deps/dsm_sdk.s']:
        add(sdk/name)
    for p in target_lib.glob('*.rlib'):
        add(p)
    for pattern in ['*LLVM*','*rustc_driver*']:
        for p in (sysroot/'lib').glob(pattern):
            add(p)
    for p in (tool.parent/'lib').glob('*.dylib'):
        add(p)
    for p in sdk.glob('build/**/output'):
        add(p)
    for name in ['rustc','cargo']:
        add(sysroot/'bin'/name)
    for name in ['aarch64-linux-android28-clang','clang','clang-18','ld.lld','llvm-ar','llvm-readelf','llvm-nm']:
        add(tool/name)
    add(ndk/'source.properties')
    # These are build-time link interfaces, not the device's libc implementation.
    interfaces = ndk/'toolchains/llvm/prebuilt/darwin-x86_64/sysroot/usr/lib/aarch64-linux-android'
    for name in ['crtbegin_so.o','crtend_so.o','libc.so','libdl.so','libm.so','liblog.so']:
        add(interfaces/'28'/name)
    for p in interfaces.glob('*.a'):
        add(p)
    ir = sdk/'deps/dsm_sdk.ll'
    cpus = set()
    features = set()
    with ir.open() as stream:
        for line in stream:
            cpus.update(re.findall(r'"target-cpu"="([^"]+)"', line))
            features.update(re.findall(r'"target-features"="([^"]+)"', line))
    if cpus != {'generic'} or features != {'+v8a,+neon,+fp-armv8'}:
        raise SystemExit('Unexpected CPU/ISA attributes require an updated target charter')
    needed = command(str(tool/'llvm-readelf'), '-d', str(sdk/'libdsm_sdk.so'))
    out.mkdir(parents=True, exist_ok=True)
    inventory = out/'FILES.tsv'
    inventory.write_text('sha256\tabsolute_path\n' + ''.join(f'{sha(p)}\t{p}\n' for p in sorted(files)))
    rustc = command('rustc','-Vv')
    meta = {
        'status':'identity evidence only; no compiler/ISA/JNI simulation',
        'invocation_directory':str(repo),
        'lock_environment_observation':'; '.join(f"{k}={os.environ.get(k, '<unset>')}" for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','CARGO_BUILD_RUSTFLAGS','CARGO_PROFILE_RELEASE_LTO','CARGO_PROFILE_RELEASE_PANIC','CARGO_PROFILE_RELEASE_CODEGEN_UNITS']),
        'source_commit':command('git','-C',str(repo),'rev-parse','HEAD'),
        'source_tree':command('git','-C',str(repo),'rev-parse','HEAD^{tree}'),
        'inventory':str(inventory),'inventory_sha256':sha(inventory),
        'target':'aarch64-linux-android','api':'28','cpu':','.join(sorted(cpus)),
        'features':','.join(sorted(features)),'rustc':rustc,
        'linker':command(str(tool/'aarch64-linux-android28-clang'),'--version'),
        'binutils':command(str(tool/'llvm-ar'),'--version'),
        'sdk_rustc_invocation':flags,
        'profile':'opt=3; overflow checks on; embed bitcode off; Cargo default LTO off; panic unwind; default codegen units',
        'allocator':'Rust std System boundary; Android allocator/runtime semantics not modeled',
        'linked_runtime_interfaces':needed,
        'unlocked_runtime':'device libc/libdl/libm/liblog, JVM, OS, allocator state, scheduling, signals and microarchitecture',
    }
    (out/'LOCK.toml').write_text('\n'.join(f'{k} = {quote(v)}' for k,v in meta.items())+'\n')
    print(f'Locked {len(files)} build files; device runtime identity and semantic proofs remain open.')
    check(out/'LOCK.toml')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',type=pathlib.Path)
    parser.add_argument('--build-log',type=pathlib.Path)
    parser.add_argument('--ndk',type=pathlib.Path)
    parser.add_argument('--out',type=pathlib.Path)
    args = parser.parse_args()
    if args.check:
        check(args.check)
    elif all([args.build_log,args.ndk,args.out]):
        lock(args)
    else:
        parser.error('Supply --check or --build-log, --ndk and --out')
