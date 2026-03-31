<#
.SYNOPSIS
    DSM Protocol — Windows developer script (PowerShell equivalent of the Makefile).

.DESCRIPTION
    All common developer tasks: build, test, storage-node management, frontend.
    Android APK builds require WSL2 — see docs/book/03-development-setup.md#windows-setup.

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
    Write-Host "    nodes-up      Set up DB and start 5 local storage nodes" -ForegroundColor Gray
    Write-Host "    nodes-down    Stop local storage nodes" -ForegroundColor Gray
    Write-Host "    nodes-status  Check local storage node health" -ForegroundColor Gray
    Write-Host "    db-setup      Create dev PostgreSQL role + database" -ForegroundColor Gray
    Write-Host "    clean         Remove all build artifacts" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Android builds require WSL2 — run 'make android' inside WSL2." -ForegroundColor Yellow
    Write-Host "  See docs/book/03-development-setup.md for Windows setup instructions." -ForegroundColor Yellow
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
        Warn "Required for nodes-up / db-setup targets"
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
    Write-Host "  Install WSL2 + Ubuntu, then follow docs/book/03-development-setup.md inside WSL2." -ForegroundColor Yellow
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

function Invoke-DbSetup {
    Step "Setting up dev PostgreSQL databases..."
    Require "psql" "Install PostgreSQL: https://www.postgresql.org/download/windows/"

    $Env:PGHOST = if ($Env:PGHOST) { $Env:PGHOST } else { "localhost" }
    $Env:PGPORT = if ($Env:PGPORT) { $Env:PGPORT } else { "5432" }
    $Env:PGUSER = if ($Env:PGUSER) { $Env:PGUSER } else { "postgres" }
    $DbUser = "dsm"
    $DbPass = "dsm"

    function PsqlExec([string]$sql, [string]$db = "postgres") {
        $result = & psql -h $Env:PGHOST -p $Env:PGPORT -U $Env:PGUSER -d $db -tAc $sql 2>&1
        return $result
    }

    # Create role if missing
    $roleExists = PsqlExec "SELECT 1 FROM pg_roles WHERE rolname='$DbUser'"
    if ($roleExists -ne "1") {
        PsqlExec "CREATE ROLE $DbUser LOGIN PASSWORD '$DbPass'" | Out-Null
        Ok "Created role: $DbUser"
    } else {
        Ok "Role $DbUser already exists"
    }

    # Create 5 databases (one per storage node)
    for ($i = 1; $i -le 5; $i++) {
        $dbName = "dsm_storage_$i"
        $dbExists = PsqlExec "SELECT 1 FROM pg_database WHERE datname='$dbName'"
        if ($dbExists -ne "1") {
            PsqlExec "CREATE DATABASE $dbName OWNER $DbUser" | Out-Null
            PsqlExec "GRANT ALL PRIVILEGES ON DATABASE $dbName TO $DbUser" | Out-Null
            Ok "Created database: $dbName"
        } else {
            Ok "Database $dbName already exists"
        }
    }

    # Apply schema if present
    $SchemaFile = Join-Path $RepoRoot "dsm_storage_node\setup_dsm_db.sql"
    if (Test-Path $SchemaFile) {
        for ($i = 1; $i -le 5; $i++) {
            $dbName = "dsm_storage_$i"
            & psql -h $Env:PGHOST -p $Env:PGPORT -U $DbUser -d $dbName -f $SchemaFile | Out-Null
        }
        Ok "Schema applied to all databases."
    }

    Ok "Database setup complete."
}

function Invoke-NodesUp {
    Step "Starting DSM storage nodes (5 nodes)..."
    Require "cargo"  "Install Rust from https://rustup.rs"

    Set-Location $RepoRoot

    # Build the storage node binary if needed
    if (-not (Test-Path "target\debug\dsm_storage_node.exe") -and
        -not (Test-Path "target\release\dsm_storage_node.exe")) {
        Step "Building storage node binary first..."
        cargo build --locked -p dsm_storage_node
    }

    $Binary = if (Test-Path "target\release\dsm_storage_node.exe") {
        "target\release\dsm_storage_node.exe"
    } else {
        "target\debug\dsm_storage_node.exe"
    }

    $Ports = @(8080, 8081, 8082, 8083, 8084)
    $Pids  = @()

    for ($i = 0; $i -lt 5; $i++) {
        $port    = $Ports[$i]
        $dataDir = Join-Path $RepoRoot "data-dev-node$($i+1)"
        New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

        $logFile = Join-Path $RepoRoot "logs\node$($i+1).log"
        New-Item -ItemType Directory -Force -Path (Split-Path $logFile) | Out-Null

        $proc = Start-Process -FilePath $Binary `
            -ArgumentList "--port", $port, "--data-dir", $dataDir `
            -RedirectStandardOutput $logFile `
            -RedirectStandardError  "$logFile.err" `
            -PassThru -NoNewWindow
        $Pids += $proc.Id
        Ok "Node $($i+1) started (port $port, PID $($proc.Id))"
    }

    # Write PIDs file for nodes-down
    $PidFile = Join-Path $RepoRoot ".nodes.pids"
    $Pids -join "`n" | Set-Content $PidFile
    Ok "Nodes running. PIDs saved to .nodes.pids"
    Ok "Stop with: .\scripts\dev.ps1 nodes-down"
}

function Invoke-NodesDown {
    Step "Stopping DSM storage nodes..."
    $PidFile = Join-Path $RepoRoot ".nodes.pids"

    if (-not (Test-Path $PidFile)) {
        Warn ".nodes.pids not found — nothing to stop (or nodes were not started with this script)"
        return
    }

    Get-Content $PidFile | ForEach-Object {
        $pid = [int]$_
        try {
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
            Ok "Stopped PID $pid"
        } catch {
            Warn "Could not stop PID $pid (may have already exited)"
        }
    }

    Remove-Item $PidFile -ErrorAction SilentlyContinue
    Ok "Nodes stopped."
}

function Invoke-NodesStatus {
    Step "Checking DSM storage node health..."
    $Ports = @(8080, 8081, 8082, 8083, 8084)
    $Running = 0

    foreach ($Port in $Ports) {
        try {
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v2/health" -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                Ok "Node on port $Port: healthy"
                $Running++
            } else {
                Warn "Node on port $Port: HTTP $($response.StatusCode)"
            }
        } catch {
            Warn "Node on port $Port: not responding"
        }
    }

    Write-Host ""
    if ($Running -eq $Ports.Length) {
        Ok "All local storage nodes are healthy."
    } elseif ($Running -eq 0) {
        Warn "No local storage nodes are responding."
    } else {
        Warn "$Running/$($Ports.Length) local storage nodes are responding."
    }
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
    "db-setup"      { Invoke-DbSetup }
    "nodes-up"      { Invoke-DbSetup; Invoke-NodesUp }
    "nodes-down"    { Invoke-NodesDown }
    "nodes-status"  { Invoke-NodesStatus }
    "clean"         { Invoke-Clean }
    default         { Fail "Unknown target: '$Target'. Run '.\scripts\dev.ps1 help'" }
}
