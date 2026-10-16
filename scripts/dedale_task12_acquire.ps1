param(
    [string]$Sources = 'data/manifests/dedale-sources.json',
    [string]$DataRoot = 'data/dedale/raw',
    [ValidateRange(1, 12)][int]$Connections = 6,
    [ValidateRange(8, 256)][int]$ChunkMiB = 64
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$env:SSLKEYLOGFILE = $null
$sourceConfig = Get-Content -LiteralPath $Sources -Raw | ConvertFrom-Json
if ($sourceConfig.version -ne '2.1' -or $sourceConfig.doi -ne '10.57745/Y5JLDG') {
    throw 'Only the pinned official DEDALE V2.1 source is supported.'
}
$dataPath = [IO.Path]::GetFullPath($DataRoot)
New-Item -ItemType Directory -Force -Path $dataPath | Out-Null
foreach ($archive in $sourceConfig.archives) {
    if ([IO.Path]::GetFileName($archive.path) -cne $archive.path) { throw 'Unsafe archive path.' }
    if ($archive.url -cne ('https://entrepot.recherche.data.gouv.fr/api/access/datafile/' + $archive.datafile_id)) { throw 'Untrusted download URL.' }
    $destination = Join-Path $dataPath $archive.path
    if (Test-Path -LiteralPath $destination) {
        if ((Get-Item -LiteralPath $destination).Length -ne $archive.bytes) { throw "Wrong completed archive size: $destination" }
        if ((Get-FileHash -LiteralPath $destination -Algorithm MD5).Hash.ToLowerInvariant() -cne $archive.md5) { throw "Wrong completed archive MD5: $destination" }
        Write-Output "Already verified: $($archive.path)"
        continue
    }
    $chunkDir = $destination + '.chunks'
    New-Item -ItemType Directory -Force -Path $chunkDir | Out-Null
    $chunkBytes = [long]$ChunkMiB * 1MB
    $partial = $destination + '.part'
    # Preserve a previously downloaded contiguous prefix. Only complete chunks
    # are reused; the final official checksum still verifies every byte.
    if (Test-Path -LiteralPath $partial) {
        $prefixStream = [IO.File]::Open($partial, 'Open', 'Read', 'ReadWrite')
        try {
            $prefixSize = $prefixStream.Length
            for ($offset = 0L; $offset + $chunkBytes -le $prefixSize; $offset += $chunkBytes) {
                $partPath = Join-Path $chunkDir (([long]($offset / $chunkBytes)).ToString('D6') + '.chunk')
                if (Test-Path -LiteralPath $partPath) { continue }
                $prefixStream.Position = $offset
                $buffer = [byte[]]::new($chunkBytes)
                $read = 0
                while ($read -lt $buffer.Length) {
                    $n = $prefixStream.Read($buffer, $read, $buffer.Length - $read)
                    if ($n -eq 0) { throw 'Unexpected end of contiguous prefix.' }
                    $read += $n
                }
                [IO.File]::WriteAllBytes($partPath, $buffer)
            }
        } finally { $prefixStream.Dispose() }
    }
    $jobs = for ($offset = 0L; $offset -lt $archive.bytes; $offset += $chunkBytes) {
        [pscustomobject]@{
            Start = $offset
            End = [Math]::Min($offset + $chunkBytes - 1, $archive.bytes - 1)
            Index = [long]($offset / $chunkBytes)
            Total = [long]$archive.bytes
            Url = $archive.url
            Directory = $chunkDir
        }
    }
    Write-Output "Acquiring $($archive.path): $($archive.bytes) bytes, $Connections concurrent ranges."
    $jobs | ForEach-Object -ThrottleLimit $Connections -Parallel {
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'
        $job = $_
        $chunkPath = Join-Path $job.Directory ($job.Index.ToString('D6') + '.chunk')
        $expected = $job.End - $job.Start + 1
        if ((Test-Path -LiteralPath $chunkPath) -and (Get-Item -LiteralPath $chunkPath).Length -eq $expected) { return }
        $pendingPath = $chunkPath + '.pending'
        for ($attempt = 1; $attempt -le 4; $attempt++) {
            try {
                $response = Invoke-WebRequest -Uri $job.Url -Headers @{Range="bytes=$($job.Start)-$($job.End)"} -OutFile $pendingPath -PassThru -TimeoutSec 240
                $range = [string]($response.Headers['Content-Range'] -join '')
                if ($response.StatusCode -ne 206 -or $range -cne "bytes $($job.Start)-$($job.End)/$($job.Total)" -or (Get-Item -LiteralPath $pendingPath).Length -ne $expected) {
                    throw 'Server did not return the exact requested byte range.'
                }
                Move-Item -LiteralPath $pendingPath -Destination $chunkPath -Force
                Write-Output "Range $($job.Index) complete ($expected bytes)."
                break
            } catch {
                if ($attempt -eq 4) { throw }
                Start-Sleep -Seconds ([Math]::Min($attempt * 2, 8))
            }
        }
    }
    # Assemble only after every range has succeeded. Reuse the partial file;
    # individual chunks remain until final checksum verification succeeds.
    $assembled = [IO.File]::Open($partial, 'Create', 'Write', 'None')
    try {
        foreach ($job in $jobs) {
            $chunkPath = Join-Path $chunkDir ($job.Index.ToString('D6') + '.chunk')
            $inputStream = [IO.File]::OpenRead($chunkPath)
            try { $inputStream.CopyTo($assembled) } finally { $inputStream.Dispose() }
        }
    } finally { $assembled.Dispose() }
    if ((Get-Item -LiteralPath $partial).Length -ne $archive.bytes) { throw 'Assembled archive size mismatch.' }
    if ((Get-FileHash -LiteralPath $partial -Algorithm MD5).Hash.ToLowerInvariant() -cne $archive.md5) { throw 'Official archive MD5 mismatch; chunks retained for inspection.' }
    Move-Item -LiteralPath $partial -Destination $destination
    # Nonrecursive deletion is limited to the explicitly enumerated chunk files
    # inside the checked data root; never remove a computed directory tree.
    foreach ($job in $jobs) {
        $chunkPath = Join-Path $chunkDir ($job.Index.ToString('D6') + '.chunk')
        Remove-Item -LiteralPath $chunkPath
    }
    Write-Output "Official MD5 verified: $($archive.path); SHA256=$((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant())"
}
