#!/usr/bin/env pwsh
# =============================================================================
#  Local CI Pipeline  —  AgentiAI RL Agent
#  Place at:  c:\Users\anant\Desktop\AgentiAI\ci_local.ps1
#  Run with:  .\ci_local.ps1
#  Optionally install as a Git pre-commit hook (see bottom of this file)
# =============================================================================

param(
    [switch]$Fast,        # run only @fast tests
    [switch]$Benchmark,   # run benchmark suite + save results
    [switch]$Full,        # run everything including @slow (default)
    [switch]$Compare,     # compare benchmarks against last saved run
    [switch]$Install      # install this script as a git pre-commit hook
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Colours ───────────────────────────────────────────────────────────────────
function Write-Header  { param($t) Write-Host "`n━━━ $t ━━━" -ForegroundColor Cyan  }
function Write-Success { param($t) Write-Host "✅  $t"       -ForegroundColor Green }
function Write-Failure { param($t) Write-Host "❌  $t"       -ForegroundColor Red   }
function Write-Info    { param($t) Write-Host "ℹ   $t"       -ForegroundColor Yellow}

$Root     = $PSScriptRoot
$TestFile = "tests\test_rl_agent_suite_v2.py"
$Start    = Get-Date
$Passed   = @()
$Failed   = @()

Push-Location $Root

# ── Install hook ──────────────────────────────────────────────────────────────
if ($Install) {
    $hookDir  = ".git\hooks"
    $hookFile = "$hookDir\pre-commit"
    if (-not (Test-Path $hookDir)) { New-Item -ItemType Directory -Path $hookDir | Out-Null }
    @"
#!/bin/sh
# Auto-generated pre-commit hook — runs fast RL agent tests
powershell -ExecutionPolicy Bypass -File "$Root\ci_local.ps1" -Fast
"@ | Set-Content $hookFile -Encoding ASCII
    Write-Success "Pre-commit hook installed at $hookFile"
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════════
# Stage 1 — Dependency check
# ══════════════════════════════════════════════════════════════════════════════
Write-Header "Stage 1 · Dependency Check"

$deps = @("pytest", "pytest-benchmark")
foreach ($dep in $deps) {
    $check = python -m pip show $dep 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Info "$dep not found — installing..."
        python -m pip install $dep --quiet
        if ($LASTEXITCODE -ne 0) { Write-Failure "Cannot install $dep"; exit 1 }
    }
}
Write-Success "All dependencies present"
$Passed += "Dependency Check"

# ══════════════════════════════════════════════════════════════════════════════
# Stage 2 — Lint  (basic syntax check, no flake8 required)
# ══════════════════════════════════════════════════════════════════════════════
Write-Header "Stage 2 · Syntax Check"

python -m py_compile $TestFile 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Success "Syntax OK"
    $Passed += "Syntax Check"
} else {
    Write-Failure "Syntax error in $TestFile"
    $Failed += "Syntax Check"
}

# ══════════════════════════════════════════════════════════════════════════════
# Stage 3 — Fast tests  (always runs)
# ══════════════════════════════════════════════════════════════════════════════
Write-Header "Stage 3 · Fast Tests (@fast marker)"

python -m pytest $TestFile -m fast -v 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Success "Fast tests passed"
    $Passed += "Fast Tests"
} else {
    Write-Failure "Fast tests FAILED"
    $Failed += "Fast Tests"
}

# ══════════════════════════════════════════════════════════════════════════════
# Stage 4 — Slow tests  (skipped with -Fast flag)
# ══════════════════════════════════════════════════════════════════════════════
if (-not $Fast) {
    Write-Header "Stage 4 · Slow Tests (@slow marker)"
    python -m pytest $TestFile -m slow -v 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Slow tests passed"
        $Passed += "Slow Tests"
    } else {
        Write-Failure "Slow tests FAILED"
        $Failed += "Slow Tests"
    }
} else {
    Write-Info "Skipping slow tests (-Fast flag active)"
}

# ══════════════════════════════════════════════════════════════════════════════
# Stage 5 — Benchmarks  (only with -Benchmark or -Full)
# ══════════════════════════════════════════════════════════════════════════════
if ($Benchmark -or $Full) {
    Write-Header "Stage 5 · Benchmark Tests"

    if ($Compare) {
        Write-Info "Comparing against previous benchmark run..."
        python -m pytest $TestFile -m benchmark --benchmark-compare --benchmark-compare-fail=mean:10% 2>&1
    } else {
        python -m pytest $TestFile -m benchmark --benchmark-autosave --benchmark-json=".benchmarks\latest.json" 2>&1
    }

    if ($LASTEXITCODE -eq 0) {
        Write-Success "Benchmarks passed"
        $Passed += "Benchmarks"
    } else {
        Write-Failure "Benchmarks FAILED (latency regression or threshold exceeded)"
        $Failed += "Benchmarks"
    }
} else {
    Write-Info "Skipping benchmarks (use -Benchmark or -Full to enable)"
}

# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════
$Elapsed = ((Get-Date) - $Start).TotalSeconds
Write-Host ("`n" + ("=" * 60)) -ForegroundColor White
Write-Host " CI SUMMARY  —  $([math]::Round($Elapsed,1))s elapsed" -ForegroundColor White
Write-Host ("=" * 60) -ForegroundColor White

foreach ($s in $Passed) { Write-Success $s }
foreach ($f in $Failed) { Write-Failure $f }

if ($Failed.Count -gt 0) {
    Write-Host "`n  $($Failed.Count) stage(s) failed. Fix issues before committing." -ForegroundColor Red
    Pop-Location
    exit 1
} else {
    Write-Host "`n  All $($Passed.Count) stages passed. Good to go! 🚀" -ForegroundColor Green
    Pop-Location
    exit 0
}

# =============================================================================
# HOW TO INSTALL AS A GIT PRE-COMMIT HOOK:
#   .\ci_local.ps1 -Install
#
# USAGE EXAMPLES:
#   .\ci_local.ps1              # fast + slow tests
#   .\ci_local.ps1 -Fast        # only @fast tests (used by pre-commit hook)
#   .\ci_local.ps1 -Benchmark   # fast + benchmarks (saves results)
#   .\ci_local.ps1 -Full        # everything
#   .\ci_local.ps1 -Full -Compare   # everything + regression check vs last benchmark
# =============================================================================
