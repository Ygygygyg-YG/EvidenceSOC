param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('original', 'crosspath')]
    [string]$Build,
    [ValidateRange(1, 24)]
    [int]$Workers = 8
)

$ErrorActionPreference = 'Stop'
$dedaleProject = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $dedaleProject
$dedaleResearch = Join-Path $dedaleProject 'data/dedale/research'
[IO.Directory]::CreateDirectory($dedaleResearch) | Out-Null
$dedaleRunId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmss.fffffffZ')
$dedalePrefix = Join-Path $dedaleResearch "prepare-$Build-$dedaleRunId"
$dedaleStatePath = "$dedalePrefix.json"
$dedaleStdout = "$dedalePrefix.stdout.log"
$dedaleStderr = "$dedalePrefix.stderr.log"
$dedalePython = Join-Path $dedaleProject 'services/backend/.venv/Scripts/python.exe'
$dedaleArguments = @('-u', '-B')
$dedaleSharedArguments = @(
    '--sources', 'data/manifests/dedale-sources.json',
    '--splits', 'data/manifests/dedale-splits.json',
    '--label-policy', 'data/manifests/dedale-label-policy.json',
    '--data-root', 'data/dedale/raw',
    '--workers', [string]$Workers,
    '--late-projection'
)
$dedaleReport = $null
if ($Build -eq 'original') {
    $dedaleArguments += @('-m', 'evals.datasets.dedale.build_manifests')
    $dedaleArguments += $dedaleSharedArguments
    $dedaleArguments += @(
        '--output-root', 'data/dedale/cases',
        '--checkpoint-root', 'data/dedale/checkpoints-original'
    )
} else {
    $dedaleReport = Join-Path $dedaleResearch "task12-crosspath-$dedaleRunId.json"
    $dedaleArguments += @('scripts/dedale_task12_crosspath_check.py')
    $dedaleArguments += $dedaleSharedArguments
    $dedaleArguments += @(
        '--cases-root', 'data/dedale/cases',
        '--rebuild-root', 'data/dedale/crosspath-cases',
        '--rebuild-data-root', 'data/dedale/crosspath-raw',
        '--output', $dedaleReport,
        '--checkpoint-root', 'data/dedale/checkpoints-crosspath',
        '--reuse-copied-sources'
    )
}
$dedaleState = [ordered]@{
    schema_version = 1
    build = $Build
    status = 'running'
    supervisor_pid = $PID
    started_at = [DateTime]::UtcNow.ToString('o')
    finished_at = $null
    python = $dedalePython
    arguments = $dedaleArguments
    stdout = $dedaleStdout
    stderr = $dedaleStderr
    crosspath_report = $dedaleReport
    exit_code = $null
    error_type = $null
}
function Write-DedaleRunState {
    $dedalePending = "$dedaleStatePath.pending"
    [IO.File]::WriteAllText(
        $dedalePending,
        (($dedaleState | ConvertTo-Json -Depth 8) + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    Move-Item -LiteralPath $dedalePending -Destination $dedaleStatePath -Force
}
Write-DedaleRunState
$dedaleExitCode = 1
try {
    & $dedalePython @dedaleArguments 1> $dedaleStdout 2> $dedaleStderr
    $dedaleExitCode = $LASTEXITCODE
    if ($dedaleExitCode -eq 0 -and $Build -eq 'crosspath') {
        $dedaleResult = Get-Content -LiteralPath $dedaleReport -Raw | ConvertFrom-Json
        if ($dedaleResult.all_equal -ne $true) {
            throw 'Cross-path process returned success without matching artifacts'
        }
        $dedaleCanonicalReport = Join-Path $dedaleResearch 'task12-crosspath-report.json'
        if (Test-Path -LiteralPath $dedaleCanonicalReport) {
            if ((Get-FileHash -LiteralPath $dedaleCanonicalReport -Algorithm SHA256).Hash -ne
                (Get-FileHash -LiteralPath $dedaleReport -Algorithm SHA256).Hash) {
                throw 'Preserve existing canonical cross-path report before replacing it'
            }
        } else {
            Copy-Item -LiteralPath $dedaleReport -Destination $dedaleCanonicalReport
        }
    }
    $dedaleState.status = if ($dedaleExitCode -eq 0) { 'prepared_not_frozen' } else { 'failed' }
} catch {
    $dedaleExitCode = 1
    $dedaleState.status = 'failed'
    $dedaleState.error_type = $_.Exception.GetType().Name
} finally {
    $dedaleState.exit_code = $dedaleExitCode
    $dedaleState.finished_at = [DateTime]::UtcNow.ToString('o')
    Write-DedaleRunState
}
exit $dedaleExitCode
