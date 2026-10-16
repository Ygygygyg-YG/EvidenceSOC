param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('original', 'crosspath')]
    [string]$Build,
    [Parameter(Mandatory = $true)]
    [string]$OriginalPreparationState,
    [Parameter(Mandatory = $true)]
    [string]$CrosspathPreparationState,
    [string]$OriginalFinalState,
    [ValidateRange(1, 8)]
    [int]$Workers = 8,
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
$dedaleProject = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $dedaleProject
$dedaleResearch = Join-Path $dedaleProject 'data/dedale/research'
$dedalePython = Join-Path $dedaleProject 'services/backend/.venv/Scripts/python.exe'
$dedaleRunId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmss.fffffffZ')
$dedalePrefix = Join-Path $dedaleResearch "finalize-$Build-$dedaleRunId"
$dedaleStatePath = "$dedalePrefix.json"
$dedaleStdout = "$dedalePrefix.stdout.log"
$dedaleStderr = "$dedalePrefix.stderr.log"
$dedaleReport = Join-Path $dedaleResearch "task12-final-crosspath-$dedaleRunId.json"
$dedaleConfigs = @(
    'data/manifests/dedale-sources.json',
    'data/manifests/dedale-scan-splits-v2.json',
    'data/manifests/dedale-neutral-policy-v3.json',
    'data/manifests/dedale-label-policy.json',
    'evals/datasets/dedale/parse.py',
    'evals/datasets/dedale/build_manifests.py',
    'evals/datasets/dedale/scan.py',
    'evals/datasets/dedale/join_labels.py',
    'evals/datasets/dedale/common.py',
    'evals/datasets/dedale/checkpoint.py',
    'evals/datasets/dedale/neutralize.py',
    'scripts/dedale_task12_finalize.py',
    'scripts/dedale_task12_crosspath_check.py',
    'scripts/dedale_task12_final_crosspath.py',
    'scripts/dedale_task12_stage_inventory.py'
)
$dedaleHashes = [ordered]@{}
foreach ($dedaleRelative in $dedaleConfigs) {
    $dedaleHashes[$dedaleRelative] = (Get-FileHash -LiteralPath $dedaleRelative -Algorithm SHA256).Hash.ToLowerInvariant()
}
$dedaleShared = @(
    '--sources', 'data/manifests/dedale-sources.json',
    '--scan-splits', 'data/manifests/dedale-scan-splits-v2.json',
    '--splits', 'data/manifests/dedale-neutral-policy-v3.json',
    '--label-policy', 'data/manifests/dedale-label-policy.json',
    '--data-root', 'data/dedale/raw',
    '--prepared-root', 'data/dedale/cases',
    '--preparation-checkpoints', 'data/dedale/checkpoints-original',
    '--workers', [string]$Workers
)
if ($Build -eq 'original') {
    $dedaleArguments = @('-u', '-B', 'scripts/dedale_task12_finalize.py') + $dedaleShared + @(
        '--output-root', 'data/dedale/final-cases',
        '--work-root', 'data/dedale/final-controls-original'
    )
    $dedalePrerequisites = @($OriginalPreparationState)
} else {
    if ([string]::IsNullOrWhiteSpace($OriginalFinalState)) {
        throw 'Crosspath finalization requires the original final supervisor state'
    }
    $dedaleArguments = @('-u', '-B', 'scripts/dedale_task12_final_crosspath.py') + $dedaleShared + @(
        '--rebuild-data-root', 'data/dedale/crosspath-raw',
        '--cases-root', 'data/dedale/final-cases',
        '--rebuild-root', 'data/dedale/final-crosspath-cases',
        '--rebuild-prepared-root', 'data/dedale/crosspath-cases',
        '--rebuild-preparation-checkpoints', 'data/dedale/checkpoints-crosspath',
        '--work-root', 'data/dedale/final-controls-crosspath',
        '--output', $dedaleReport
    )
    $dedalePrerequisites = @($OriginalPreparationState, $CrosspathPreparationState, $OriginalFinalState)
}
foreach ($dedalePrerequisite in $dedalePrerequisites) {
    if (-not (Test-Path -LiteralPath $dedalePrerequisite -PathType Leaf)) {
        throw "Preparation state missing: $dedalePrerequisite"
    }
}
$dedaleState = [ordered]@{
    schema_version = 1
    protocol = 'dedale-neutral-v3'
    build = $Build
    status = 'waiting_for_preparation'
    supervisor_pid = $PID
    started_at = [DateTime]::UtcNow.ToString('o')
    finished_at = $null
    prerequisites = $dedalePrerequisites
    input_and_code_sha256 = $dedaleHashes
    arguments = $dedaleArguments
    stdout = $dedaleStdout
    stderr = $dedaleStderr
    crosspath_report = $(if ($Build -eq 'crosspath') { $dedaleReport } else { $null })
    formal_model_runs = 0
    freeze_eligible = $false
    exit_code = $null
    error = $null
}
if ($ValidateOnly) {
    $dedaleState | ConvertTo-Json -Depth 8
    exit 0
}
function Save-DedaleFinalState {
    $dedalePending = "$dedaleStatePath.pending"
    [IO.File]::WriteAllText($dedalePending, ($dedaleState | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $dedalePending -Destination $dedaleStatePath -Force
}
Save-DedaleFinalState
try {
    do {
        $dedaleReady = $true
        foreach ($dedalePrerequisite in $dedalePrerequisites) {
            $dedalePrevious = Get-Content -LiteralPath $dedalePrerequisite -Raw | ConvertFrom-Json
            if ($dedalePrevious.status -in @('failed', 'stopped')) {
                throw "Preparation did not complete: $dedalePrerequisite ($($dedalePrevious.status))"
            }
            if ($dedalePrevious.status -ne 'prepared_not_frozen' -or $dedalePrevious.exit_code -ne 0) {
                if ($dedalePrevious.status -notin @('running', 'waiting_for_preparation', 'rebuilding_neutral_cases', 'building_stage_review_packet')) {
                    throw "Unrecognized incomplete prerequisite state: $dedalePrerequisite ($($dedalePrevious.status))"
                }
                $dedaleSupervisor = Get-Process -Id $dedalePrevious.supervisor_pid -ErrorAction SilentlyContinue
                if ($null -eq $dedaleSupervisor -or $dedaleSupervisor.ProcessName -notin @('pwsh', 'powershell')) {
                    throw "Prerequisite supervisor is no longer running: $dedalePrerequisite"
                }
                $dedaleRecordedStart = if ($dedalePrevious.started_at -is [DateTime]) {
                    $dedalePrevious.started_at.ToUniversalTime()
                } else {
                    [DateTimeOffset]::Parse([string]$dedalePrevious.started_at).UtcDateTime
                }
                if ($dedaleSupervisor.StartTime.ToUniversalTime() -gt $dedaleRecordedStart) {
                    throw "Prerequisite supervisor PID has been reused: $dedalePrerequisite"
                }
                $dedaleReady = $false
            } else {
                $dedalePrerequisiteRoot = if ($dedalePrevious.protocol -eq 'dedale-neutral-v3') {
                    'data/dedale/final-cases'
                } elseif ($dedalePrevious.build -eq 'crosspath') {
                    'data/dedale/crosspath-cases'
                } else {
                    'data/dedale/cases'
                }
                if (-not (Test-Path -LiteralPath (Join-Path $dedalePrerequisiteRoot 'selection.json') -PathType Leaf)) {
                    throw "Completed prerequisite has no selection artifact: $dedalePrerequisite"
                }
            }
        }
        if ($Build -eq 'crosspath' -and -not (Test-Path -LiteralPath 'data/dedale/final-cases/selection.json' -PathType Leaf)) {
            $dedaleReady = $false
        }
        if (-not $dedaleReady) { Start-Sleep -Seconds 30 }
    } until ($dedaleReady)
    foreach ($dedaleRelative in $dedaleConfigs) {
        if ((Get-FileHash -LiteralPath $dedaleRelative -Algorithm SHA256).Hash.ToLowerInvariant() -ne $dedaleHashes[$dedaleRelative]) {
            throw "Final input or implementation changed while waiting: $dedaleRelative"
        }
    }
    $env:SSLKEYLOGFILE = ''
    $dedaleState.status = 'rebuilding_neutral_cases'
    Save-DedaleFinalState
    & $dedalePython @dedaleArguments 1>> $dedaleStdout 2>> $dedaleStderr
    $dedaleState.exit_code = $LASTEXITCODE
    if ($LASTEXITCODE -ne 0) { throw "Final curation exited with code $LASTEXITCODE" }
    if ($Build -eq 'original') {
        $dedaleState.status = 'building_stage_review_packet'
        Save-DedaleFinalState
        & $dedalePython -u -B 'scripts/dedale_task12_stage_inventory.py' `
            --cases-root 'data/dedale/final-cases' --data-root 'data/dedale/raw' `
            --scoring-source-root 'data/dedale/research/scoring-source' `
            --output 'data/dedale/research/scoring-source/selected-stage-review-packet-final-v3.json' `
            1>> $dedaleStdout 2>> $dedaleStderr
        $dedaleState.exit_code = $LASTEXITCODE
        if ($LASTEXITCODE -ne 0) { throw "Stage inventory exited with code $LASTEXITCODE" }
    } else {
        $dedaleFinalComparison = Get-Content -LiteralPath $dedaleReport -Raw | ConvertFrom-Json
        if ($dedaleFinalComparison.all_equal -ne $true) { throw 'Final crosspath artifact mismatch' }
        Copy-Item -LiteralPath $dedaleReport -Destination (Join-Path $dedaleResearch 'task12-final-crosspath-report.json')
    }
    $dedaleState.status = 'prepared_not_frozen'
} catch {
    $dedaleState.status = 'failed'
    $dedaleState.error = $_.Exception.Message
} finally {
    $dedaleState.finished_at = [DateTime]::UtcNow.ToString('o')
    Save-DedaleFinalState
}
if ($dedaleState.status -ne 'prepared_not_frozen') { exit 1 }
