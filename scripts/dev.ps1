<#
.SYNOPSIS
    DSM Protocol — Windows developer script (PowerShell equivalent of the Makefile).

.DESCRIPTION
    All common developer tasks: build, test, storage-node management, frontend.
    Android APK builds require WSL2 — see QUICKSTART.md.

.EXAMPLE
    .\scripts\dev.ps1 help
    .\scripts\dev.ps1 menu
    .\scripts\dev.ps1 setup
    .\scripts\dev.ps1 build
    .\scripts\dev.ps1 nodes-up
    .\scripts\dev.ps1 test
#>

param(
    [Parameter(Position = 0)]
    [string]$Target = "help"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Step([string]$msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok([string]$msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Warn([string]$msg) { Write-Host "    WARNING: $msg" -ForegroundColor Yellow }
function Fail([string]$msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

function Require([string]$cmd, [string]$installHint) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Fail "$cmd not found. $installHint"
    }
}

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
function Show-Help {
    Write-Host ""
    Write-Host "DSM Protocol — Windows developer script" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Usage: .\scripts\dev.ps1 <target>" -ForegroundColor White
    Write-Host ""
    Write-Host "  Targets:" -ForegroundColor White
    Write-Host "    help          Show this help" -ForegroundColor Gray
    Write-Host "    menu          Interactive launcher" -ForegroundColor Gray
    Write-Host "    setup         Check prerequisites" -ForegroundColor Gray
    Write-Host "    doctor        Check prerequisites (alias of setup)" -ForegroundColor Gray
    Write-Host "    build         Rust workspace build" -ForegroundColor Gray
    Write-Host "    build-release Rust workspace release build" -ForegroundColor Gray
    Write-Host "    frontend      Build the React frontend" -ForegroundColor Gray
    Write-Host "    test          Run Rust + frontend tests" -ForegroundColor Gray
    Write-Host "    test-rust     Run Rust tests only" -ForegroundColor Gray
    Write-Host "    test-frontend Run frontend jest tests only" -ForegroundColor Gray
    Write-Host "    typecheck     Frontend TypeScript type-check" -ForegroundColor Gray
    Write-Host "    lint          cargo fmt check + clippy" -ForegroundColor Gray
    Write-Host "    fmt           Auto-format Rust code" -ForegroundColor Gray
    Write-Host "    nodes-up      Start your own local storage set (5 nodes; needs PostgreSQL)" -ForegroundColor Gray
    Write-Host "    nodes-down    Stop the local storage nodes" -ForegroundColor Gray
    Write-Host "    nodes-status  Health of every local node, over verified TLS" -ForegroundColor Gray
    Write-Host "    nodes-reset   Stop the nodes, drop their databases, forget the set" -ForegroundColor Gray
    Write-Host "    clean         Remove all build artifacts" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Android builds require WSL2 — run 'make android' inside WSL2." -ForegroundColor Yellow
    Write-Host "  See QUICKSTART.md for Windows setup instructions." -ForegroundColor Yellow
    Write-Host ""
}

function Show-Menu {
    $options = @(
        "setup",
        "build",
        "frontend",
        "test",
        "lint",
        "nodes-up",
        "nodes-down",
        "nodes-status",
        "clean",
        "quit"
    )

    Write-Host ""
    Write-Host "DSM Protocol — interactive launcher" -ForegroundColor Cyan
    for ($i = 0; $i -lt $options.Length; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $options[$i]) -ForegroundColor Gray
    }

    $choice = Read-Host "Select a task number"
    if ($choice -notmatch '^\d+$') {
        Fail "Invalid selection: '$choice'"
    }
    $index = [int]$choice - 1
    if ($index -lt 0 -or $index -ge $options.Length) {
        Fail "Selection out of range: '$choice'"
    }
    if ($options[$index] -eq "quit") {
        return
    }
    & $PSCommandPath $options[$index]
}

function Invoke-Setup {
    Step "Checking prerequisites..."

    Require "cargo"  "Install Rust from https://rustup.rs"
    Ok "cargo $(cargo --version)"

    Require "rustfmt" "Run: rustup component add rustfmt"
    Require "cargo-clippy" "Run: rustup component add clippy"

    if (-not (Get-Command "node" -ErrorAction SilentlyContinue)) {
        Warn "node not found — install Node.js 20+ from https://nodejs.org"
    } else {
        Ok "node $(node --version)"
    }

    if (-not (Get-Command "psql" -ErrorAction SilentlyContinue)) {
        Warn "psql not found — install PostgreSQL from https://www.postgresql.org/download/windows/"
        Warn "Required for the nodes-up target"
    } else {
        Ok "psql $(psql --version)"
    }

    if (-not (Get-Command "adb" -ErrorAction SilentlyContinue)) {
        Warn "adb not found — Android Platform Tools needed only for device installs"
    } else {
        Ok "adb $(adb version | Select-String 'version' | Select-Object -First 1)"
    }

    Write-Host ""
    Write-Host "  Android builds: WSL2 required (NDK toolchain not supported on Windows native)" -ForegroundColor Yellow
    Write-Host "  Install WSL2 + Ubuntu, then follow QUICKSTART.md inside WSL2." -ForegroundColor Yellow
    Write-Host ""
    Ok "Setup check complete."
}

function Invoke-Build {
    Step "Building Rust workspace..."
    Set-Location $RepoRoot
    cargo build --locked --workspace --all-features
    Ok "Build complete."
}

function Invoke-BuildRelease {
    Step "Building Rust workspace (release)..."
    Set-Location $RepoRoot
    cargo build --locked --workspace --all-features --release
    Ok "Release build complete."
}

function Invoke-Frontend {
    Step "Building frontend..."
    $FrontendDir = Join-Path $RepoRoot "dsm_client\frontend"
    Set-Location $FrontendDir
    Require "node" "Install Node.js 20+ from https://nodejs.org"
    npm ci
    npm run build
    Ok "Frontend built."
}

function Invoke-Test {
    Invoke-TestRust
    Invoke-TestFrontend
}

function Invoke-TestRust {
    Step "Running Rust tests..."
    Set-Location $RepoRoot
    cargo test --locked --workspace -- --nocapture
    Ok "Rust tests passed."
}

function Invoke-TestFrontend {
    Step "Running frontend tests..."
    $FrontendDir = Join-Path $RepoRoot "dsm_client\frontend"
    Set-Location $FrontendDir
    Require "node" "Install Node.js 20+ from https://nodejs.org"
    npm test -- --passWithNoTests --ci
    Ok "Frontend tests passed."
}

function Invoke-Typecheck {
    Step "Frontend type-check..."
    $FrontendDir = Join-Path $RepoRoot "dsm_client\frontend"
    Set-Location $FrontendDir
    Require "node" "Install Node.js 20+ from https://nodejs.org"
    npm run type-check
    Ok "Type-check passed."
}

function Invoke-Lint {
    Step "Running linters..."
    Set-Location $RepoRoot
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
    Ok "Lint passed."
}

function Invoke-Fmt {
    Step "Formatting Rust code..."
    Set-Location $RepoRoot
    cargo fmt --all
    Ok "Format complete."
}

# ---------------------------------------------------------------------------
# Local storage set (the same as `make nodes-up`): the network's pinned members
# as five local nodes, prepared by crates/dsm-dev-net, under .dsm-dev\net.
# ---------------------------------------------------------------------------
$DevNet     = Join-Path $RepoRoot ".dsm-dev\net"
$ExeSuffix  = if ($IsWindows -or $Env:OS -eq "Windows_NT") { ".exe" } else { "" }
$NodeBin    = Join-Path $RepoRoot "target\release\storage_node$ExeSuffix"
$DevNetBin  = Join-Path $RepoRoot "target\release\dsm-dev-net$ExeSuffix"

function Get-DevPgUrl {
    if ($Env:DSM_DEV_PG_URL) { return $Env:DSM_DEV_PG_URL }
    $user = if ($Env:PGUSER) { $Env:PGUSER } elseif ($Env:USERNAME) { $Env:USERNAME } else { $Env:USER }
    return "postgresql://$user@localhost:5432/postgres?sslmode=disable"
}

function Build-DevNet {
    Require "cargo" "Install Rust from https://rustup.rs"
    Set-Location $RepoRoot
    Step "Building the storage node and dsm-dev-net (release)..."
    cargo build --release --locked -p dsm_storage_node -p dsm-dev-net
    if ($LASTEXITCODE -ne 0) { Fail "the build failed" }
}

function Get-DevMembers {
    Get-ChildItem -Path $DevNet -Filter "dsm-node-*.toml" | Sort-Object Name | ForEach-Object {
        $port = (Select-String -Path $_.FullName -Pattern '^port = (\d+)$').Matches[0].Groups[1].Value
        [pscustomobject]@{ Name = $_.BaseName; Config = $_.FullName; Port = [int]$port }
    }
}

function Test-DevNode([string]$Name, [int]$Port) {
    # Verified TLS against the member's own CA (curl ships with Windows 10+).
    & curl -fsS --cacert (Join-Path $DevNet "$Name-ca.pem") --connect-timeout 2 --max-time 5 `
        "https://127.0.0.1:$Port/api/v2/health" *> $null
    return ($LASTEXITCODE -eq 0)
}

function Invoke-NodesUp {
    Step "Starting your local storage set (5 nodes)..."
    Build-DevNet
    if (-not (Test-Path (Join-Path $DevNet "dsm_env_config.toml"))) {
        & $DevNetBin prepare --dir $DevNet --pg (Get-DevPgUrl) --first-port 8080
        if ($LASTEXITCODE -ne 0) { Fail "dsm-dev-net prepare failed" }
    }
    $logs = Join-Path $DevNet "logs"; $run = Join-Path $DevNet "run"
    New-Item -ItemType Directory -Force -Path $logs, $run | Out-Null
    $failed = 0
    foreach ($m in Get-DevMembers) {
        if (Test-DevNode $m.Name $m.Port) { Ok "$($m.Name) already serving on :$($m.Port)"; continue }
        $log = Join-Path $logs "$($m.Name).log"
        $Env:RUST_LOG = "info"
        $proc = Start-Process -FilePath $NodeBin -ArgumentList "--config", $m.Config `
            -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -NoNewWindow
        Set-Content -Path (Join-Path $run "$($m.Name).pid") -Value $proc.Id
        $up = 0
        for ($i = 0; $i -lt 40; $i++) {
            Start-Sleep -Milliseconds 500
            if (Test-DevNode $m.Name $m.Port) { $up = 1; break }
            if ($proc.HasExited) { break }
        }
        if ($up -eq 1) { Ok "$($m.Name) serving on https://127.0.0.1:$($m.Port)" }
        else { Warn "$($m.Name) did not start; see $log"; $failed = 1 }
    }
    Ok "Client config: $(Join-Path $DevNet 'dsm_env_config.toml')"
    if ($failed -ne 0) { Fail "not every node started" }
}

function Invoke-NodesDown {
    Step "Stopping your local storage set..."
    $run = Join-Path $DevNet "run"
    if (-not (Test-Path $run)) { Ok "nothing to stop"; return }
    Get-ChildItem -Path $run -Filter "*.pid" | ForEach-Object {
        $nodePid = [int](Get-Content $_.FullName)
        $proc = Get-Process -Id $nodePid -ErrorAction SilentlyContinue
        if ($proc) { Stop-Process -Id $nodePid -Force; Ok "stopped $($_.BaseName)" }
        Remove-Item $_.FullName
    }
}

function Invoke-NodesStatus {
    Step "Checking your local storage set..."
    if (-not (Test-Path (Join-Path $DevNet "dsm_env_config.toml"))) { Fail "no set prepared: .\scripts\dev.ps1 nodes-up" }
    $failed = 0
    foreach ($m in Get-DevMembers) {
        if (Test-DevNode $m.Name $m.Port) { Ok "$($m.Name) healthy on https://127.0.0.1:$($m.Port)" }
        else { Warn "$($m.Name) NOT serving on :$($m.Port)"; $failed = 1 }
    }
    if ($failed -ne 0) { Fail "not every node is serving" }
}

function Invoke-NodesReset {
    Invoke-NodesDown
    Build-DevNet
    & $DevNetBin drop --pg (Get-DevPgUrl)
    if ($LASTEXITCODE -ne 0) { Fail "dsm-dev-net drop failed" }
    if (Test-Path $DevNet) { Remove-Item -Recurse -Force $DevNet }
    Ok "forgot the set; the next nodes-up prepares a new one"
}

function Invoke-Clean {
    Step "Cleaning build artifacts..."
    Set-Location $RepoRoot
    cargo clean
    $FrontendDirs = @(
        "dsm_client\frontend\dist",
        "dsm_client\frontend\build"
    )
    foreach ($d in $FrontendDirs) {
        $full = Join-Path $RepoRoot $d
        if (Test-Path $full) { Remove-Item -Recurse -Force $full }
    }
    Ok "Clean complete."
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
switch ($Target.ToLower()) {
    "help"          { Show-Help }
    "menu"          { Show-Menu }
    "setup"         { Invoke-Setup }
    "doctor"        { Invoke-Setup }
    "build"         { Invoke-Build }
    "build-release" { Invoke-BuildRelease }
    "frontend"      { Invoke-Frontend }
    "test"          { Invoke-Test }
    "test-rust"     { Invoke-TestRust }
    "test-frontend" { Invoke-TestFrontend }
    "typecheck"     { Invoke-Typecheck }
    "lint"          { Invoke-Lint }
    "fmt"           { Invoke-Fmt }
    "nodes-up"      { Invoke-NodesUp }
    "nodes-down"    { Invoke-NodesDown }
    "nodes-status"  { Invoke-NodesStatus }
    "nodes-reset"   { Invoke-NodesReset }
    "clean"         { Invoke-Clean }
    default         { Fail "Unknown target: '$Target'. Run '.\scripts\dev.ps1 help'" }
}
