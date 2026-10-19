param(
    [Parameter(Mandatory=$true)][ValidateSet('ait','dedale')][string]$Dataset,
    [string]$Config,
    [string]$RuntimeConfig,
    [string]$OutputRoot,
    [string]$Python,
    [switch]$AllowFinalTest
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Config) { $Config = Join-Path $PSScriptRoot "configs/$Dataset.json" }
if (-not $RuntimeConfig) { $RuntimeConfig = Join-Path $repoRoot 'data/task13/runtime/runtime.json' }
if (-not $OutputRoot) { $OutputRoot = Join-Path $repoRoot "data/task13/runs/$Dataset" }
if (-not $Python) { $Python = Join-Path $repoRoot 'services/backend/.venv/Scripts/python.exe' }
if (-not $AllowFinalTest) { throw 'Formal execution requires -AllowFinalTest and every frozen gate.' }
foreach ($requiredPath in @($Config, $RuntimeConfig, $Python)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) { throw "Required explicit input missing: $requiredPath" }
}
$controller = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
if ($controller.dataset -ne $Dataset -or $controller.split -ne 'test' -or $controller.run_id -notmatch '^[A-Za-z0-9_-]{1,80}$') { throw 'Dataset/split/run identity differs from formal configuration.' }
$runRoot = Join-Path ([System.IO.Path]::GetFullPath($OutputRoot)) $controller.run_id
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
$planPath = Join-Path $runRoot 'plan.json'
$attemptRoot = Join-Path $runRoot 'attempts'
$invocationId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '-' + [Guid]::NewGuid().ToString('N')
$scorePath = Join-Path $runRoot ('scores-' + $invocationId + '.json')
$commands = @(
    @('-m','evals.runners.cli','plan','--config',$Config,'--output',$planPath),
    @('-m','evals.runners.cli','execute','--plan',$planPath,'--output-root',$attemptRoot,'--runtime-config',$RuntimeConfig,'--allow-final-test'),
    @('-m','evals.runners.cli','score','--plan',$planPath,'--output-root',$attemptRoot,'--output',$scorePath)
)
$receiptPath = Join-Path $runRoot 'commands.json'
$configHash = (Get-FileHash -LiteralPath $Config -Algorithm SHA256).Hash.ToLowerInvariant()
$runtimeHash = (Get-FileHash -LiteralPath $RuntimeConfig -Algorithm SHA256).Hash.ToLowerInvariant()
$receipt = @{ dataset=$Dataset; run_id=$controller.run_id; python=$Python; config_sha256=$configHash; runtime_sha256=$runtimeHash; commands=$commands; invocation_id=$invocationId; plan_reused=(Test-Path -LiteralPath $planPath) }
$bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($receipt | ConvertTo-Json -Depth 8) + "`n")
if (Test-Path -LiteralPath $receiptPath) {
    $previous = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    if ($previous.config_sha256 -ne $configHash -or $previous.runtime_sha256 -ne $runtimeHash) { throw 'Saved formal configuration differs; use a new run ID.' }
} else {
    $stream = [System.IO.File]::Open($receiptPath, [System.IO.FileMode]::CreateNew)
    try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
}
$invocationPath = Join-Path $runRoot ('commands-' + $invocationId + '.json')
$stream = [System.IO.File]::Open($invocationPath, [System.IO.FileMode]::CreateNew)
try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
Push-Location -LiteralPath $repoRoot
try {
    $env:UV_CACHE_DIR = Join-Path $repoRoot '.uv-cache'
    if (-not (Test-Path -LiteralPath $planPath)) {
        & $Python @($commands[0])
        if ($LASTEXITCODE -ne 0) { throw 'Formal plan failed.' }
    }
    & $Python @($commands[1])
    if ($LASTEXITCODE -ne 0) { throw 'Formal execution failed.' }
    & $Python @($commands[2])
    if ($LASTEXITCODE -ne 0) { throw 'Independent automatic scoring failed.' }
} finally { Pop-Location }
