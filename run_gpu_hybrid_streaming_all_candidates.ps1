param(
    [string]$GpuFilterExe = ".\enigma_cuda_prefix_filter.exe",
    [string]$CpuSearchExe = ".\enigma_m3_search_fast.exe",
    [string]$Tier = "2",
    [string]$Plaintext = "REALITYISACONFLUX",
    [UInt64]$StartIndex = 0,
    [UInt64]$MaxStates = 0,
    [UInt64]$ChunkStates = 100000000,
    [int]$PrefixLen = 13,
    [int]$ThreadsPerCandidate = 4,
    [int]$ProgressSeconds = 0,
    [string]$WorkDir = ".\gpu_hybrid_streaming_work",
    [string]$SummaryPath = ".\gpu_hybrid_streaming_summary.json"
)

$ErrorActionPreference = "Stop"

$candidates = @(
    [pscustomobject]@{ Id = 1; Label = "PE AF GR";    Ciphertext = "ZYZYFVWJUFEXKGPOB" },
    [pscustomobject]@{ Id = 2; Label = "PE GR UT";    Ciphertext = "JYZYAZGJTFEXKKPOB" },
    [pscustomobject]@{ Id = 3; Label = "PE AF UT";    Ciphertext = "JYZYFVRJTFEXYRPOB" },
    [pscustomobject]@{ Id = 4; Label = "AF GR UT";    Ciphertext = "JYGYGVGJTFPDKGERB" },
    [pscustomobject]@{ Id = 5; Label = "PE AF GR UT"; Ciphertext = "JYZYFVGJTFEXKGPOB" },
    [pscustomobject]@{ Id = 6; Label = "PE GR";       Ciphertext = "ZYZYAZWJUFEXKKPOB" },
    [pscustomobject]@{ Id = 7; Label = "PE AF";       Ciphertext = "ZYZYFVWJUFEXYRPOB" },
    [pscustomobject]@{ Id = 8; Label = "PE UT";       Ciphertext = "JYZYAZRJTFEXYKPOB" },
    [pscustomobject]@{ Id = 9; Label = "AF GR";       Ciphertext = "ZYGYGVWJUFPDKGERB" },
    [pscustomobject]@{ Id = 10; Label = "GR UT";      Ciphertext = "JYGYGZGJTFPDKKERB" },
    [pscustomobject]@{ Id = 11; Label = "AF UT";      Ciphertext = "JYRYRVRJTFPDYREGB" },
    [pscustomobject]@{ Id = 12; Label = "PE";         Ciphertext = "ZYZYAZWJUFEXYKPOB" },
    [pscustomobject]@{ Id = 13; Label = "GR";         Ciphertext = "ZYGYGZWJUFPDKKERB" },
    [pscustomobject]@{ Id = 14; Label = "AF";         Ciphertext = "ZYRYRVWJUFPDYREGB" },
    [pscustomobject]@{ Id = 15; Label = "UT";         Ciphertext = "JYRYRZRJTFPDYKEGB" },
    [pscustomobject]@{ Id = 16; Label = "none";       Ciphertext = "ZYRYRZWJUFPDYKEGB" }
)

if ($Tier -eq "1") {
    [UInt64]$tierTotal = 617831552
} elseif ($Tier -eq "2") {
    [UInt64]$tierTotal = 37069893120
} else {
    throw "streaming runner requires -Tier 1 or -Tier 2"
}
if ($StartIndex -ge $tierTotal) {
    throw "StartIndex is outside this tier"
}
if ($ChunkStates -lt 1) {
    throw "ChunkStates must be at least 1"
}

[UInt64]$availableStates = $tierTotal - $StartIndex
[UInt64]$statesToRun = $(if ($MaxStates -gt 0 -and $MaxStates -lt $availableStates) { $MaxStates } else { $availableStates })

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$workFullPath = (Resolve-Path -LiteralPath $WorkDir).Path
$gpuExeFullPath = (Resolve-Path -LiteralPath $GpuFilterExe).Path
$cpuExeFullPath = (Resolve-Path -LiteralPath $CpuSearchExe).Path

function Start-CpuBatch {
    param(
        [Parameter(Mandatory=$true)] [pscustomobject]$Chunk
    )

    $fullDir = Join-Path $Chunk.dir "full"
    New-Item -ItemType Directory -Force -Path $fullDir | Out-Null
    $procs = @()
    foreach ($candidate in $candidates) {
        $stateList = Join-Path $Chunk.survivor_dir ("candidate_{0}_survivors.bin" -f $candidate.Id)
        $jsonOut = Join-Path $fullDir ("candidate_{0}_full.json" -f $candidate.Id)
        $stdout = Join-Path $fullDir ("candidate_{0}.out.txt" -f $candidate.Id)
        $stderr = Join-Path $fullDir ("candidate_{0}.err.txt" -f $candidate.Id)
        $args = @(
            "--tier", $Tier,
            "--plaintext", $Plaintext,
            "--ciphertext", $candidate.Ciphertext,
            "--threads", "$ThreadsPerCandidate",
            "--state-list-binary", $stateList,
            "--progress-seconds", "$ProgressSeconds",
            "--skip-initial-tests",
            "--output", $jsonOut
        )
        $procs += Start-Process -FilePath $cpuExeFullPath -ArgumentList $args -WorkingDirectory (Get-Location).Path -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    }
    return [pscustomobject]@{
        chunk = $Chunk
        full_dir = $fullDir
        procs = $procs
        started = Get-Date
        watch = [Diagnostics.Stopwatch]::StartNew()
    }
}

function Complete-CpuBatch {
    param(
        [Parameter(Mandatory=$true)] [pscustomobject]$Batch
    )

    foreach ($proc in $Batch.procs) {
        $proc.WaitForExit()
    }
    $Batch.watch.Stop()

    $failed = $Batch.procs | Where-Object { $_.ExitCode -ne 0 -and $null -ne $_.ExitCode }
    if ($failed.Count -gt 0) {
        throw "one or more CPU full-solve processes failed for chunk $($Batch.chunk.index)"
    }

    $reportedCpuElapsed = 0.0
    $summaries = foreach ($candidate in $candidates) {
        $jsonOut = Join-Path $Batch.full_dir ("candidate_{0}_full.json" -f $candidate.Id)
        $full = Get-Content -LiteralPath $jsonOut -Raw | ConvertFrom-Json
        $tierStats = @($full.tier_stats)[0]
        $reportedCpuElapsed += [double]$tierStats.elapsed_seconds
        [pscustomobject]@{
            id = $candidate.Id
            result_count = [int]$full.result_count
            states_checked = [UInt64]$full.states_checked
            cpu_full_elapsed_seconds_reported = [double]$tierStats.elapsed_seconds
            output = $jsonOut
        }
    }

    return [pscustomobject]@{
        chunk_index = $Batch.chunk.index
        start_index = $Batch.chunk.start_index
        states = $Batch.chunk.states
        overlap_window_seconds = $Batch.watch.Elapsed.TotalSeconds
        reported_cpu_elapsed_seconds_sum = $reportedCpuElapsed
        candidates = $summaries
    }
}

$totalWatch = [Diagnostics.Stopwatch]::StartNew()
$gpuElapsedSum = 0.0
$cpuBatchOverlapWindowSum = 0.0
$cpuReportedElapsedSum = 0.0
$chunks = @()
$cpuChunks = @()
$pendingCpuBatch = $null
$previousChunk = $null

[UInt64]$processed = 0
[int]$chunkIndex = 0
while ($processed -lt $statesToRun) {
    if ($null -ne $previousChunk) {
        $pendingCpuBatch = Start-CpuBatch -Chunk $previousChunk
    }

    [UInt64]$remaining = $statesToRun - $processed
    [UInt64]$thisChunkStates = $(if ($remaining -lt $ChunkStates) { $remaining } else { $ChunkStates })
    [UInt64]$thisStart = $StartIndex + $processed

    $chunkName = "chunk_{0:D5}" -f $chunkIndex
    $chunkDir = Join-Path $workFullPath $chunkName
    $survivorDir = Join-Path $chunkDir "survivors"
    New-Item -ItemType Directory -Force -Path $survivorDir | Out-Null
    $gpuJson = Join-Path $chunkDir "gpu_prefix.json"

    & $gpuExeFullPath --tier $Tier --plaintext $Plaintext --default-candidates --start-index $thisStart --max-states $thisChunkStates --prefix-len $PrefixLen --survivor-dir $survivorDir --output $gpuJson
    if ($LASTEXITCODE -ne 0) {
        throw "GPU prefix filter failed for chunk $chunkIndex with code $LASTEXITCODE"
    }

    $gpu = Get-Content -LiteralPath $gpuJson -Raw | ConvertFrom-Json
    $gpuElapsedSum += [double]$gpu.wall_elapsed_seconds
    $chunk = [pscustomobject]@{
        index = $chunkIndex
        start_index = $thisStart
        states = $thisChunkStates
        dir = $chunkDir
        survivor_dir = $survivorDir
        gpu_output = $gpuJson
        gpu_wall_elapsed_seconds = [double]$gpu.wall_elapsed_seconds
        gpu_candidates = $gpu.candidates
    }
    $chunks += $chunk

    if ($null -ne $pendingCpuBatch) {
        $completed = Complete-CpuBatch -Batch $pendingCpuBatch
        $cpuBatchOverlapWindowSum += [double]$completed.overlap_window_seconds
        $cpuReportedElapsedSum += [double]$completed.reported_cpu_elapsed_seconds_sum
        $cpuChunks += $completed
        $pendingCpuBatch = $null
    }

    $previousChunk = $chunk
    $processed += $thisChunkStates
    ++$chunkIndex
}

if ($null -ne $previousChunk) {
    $pendingCpuBatch = Start-CpuBatch -Chunk $previousChunk
    $completed = Complete-CpuBatch -Batch $pendingCpuBatch
    $cpuBatchOverlapWindowSum += [double]$completed.overlap_window_seconds
    $cpuReportedElapsedSum += [double]$completed.reported_cpu_elapsed_seconds_sum
    $cpuChunks += $completed
}

$totalWatch.Stop()

$orderedSolutions = @()
$candidateSummaries = foreach ($candidate in $candidates) {
    [UInt64]$survivors = 0
    [int]$results = 0
    $outputs = @()
    foreach ($chunk in $chunks) {
        $gpuCandidate = @($chunk.gpu_candidates | Where-Object id -eq $candidate.Id)[0]
        if ($null -ne $gpuCandidate) {
            $survivors += [UInt64]$gpuCandidate.survivors
        }
    }
    foreach ($cpuChunk in $cpuChunks) {
        $cpuCandidate = @($cpuChunk.candidates | Where-Object id -eq $candidate.Id)[0]
        if ($null -ne $cpuCandidate) {
            $results += [int]$cpuCandidate.result_count
            $outputs += $cpuCandidate.output
            $full = Get-Content -LiteralPath $cpuCandidate.output -Raw | ConvertFrom-Json
            foreach ($result in @($full.results)) {
                $orderedSolutions += [pscustomobject]@{
                    id = $candidate.Id
                    label = $candidate.Label
                    ciphertext = $candidate.Ciphertext
                    chunk_index = $cpuChunk.chunk_index
                    output = $cpuCandidate.output
                    result = $result
                }
            }
        }
    }
    [pscustomobject]@{
        id = $candidate.Id
        label = $candidate.Label
        ciphertext = $candidate.Ciphertext
        gpu_prefix_survivors = $survivors
        result_count = $results
        outputs = $outputs
    }
}

$summary = [pscustomobject]@{
    plaintext = $Plaintext
    tier = $Tier
    candidate_count = $candidates.Count
    start_index = $StartIndex
    max_states = $(if ($MaxStates -gt 0) { $MaxStates } else { $null })
    states_to_run = $statesToRun
    chunk_states = $ChunkStates
    chunk_count = $chunks.Count
    prefix_len = $PrefixLen
    threads_per_candidate = $ThreadsPerCandidate
    total_worker_threads = $ThreadsPerCandidate * $candidates.Count
    gpu_prefix_wall_elapsed_seconds_sum = $gpuElapsedSum
    cpu_full_overlap_window_seconds_sum = $cpuBatchOverlapWindowSum
    cpu_full_reported_elapsed_seconds_sum = $cpuReportedElapsedSum
    total_wall_elapsed_seconds = $totalWatch.Elapsed.TotalSeconds
    literal_states_checked_per_candidate = $statesToRun
    aggregate_candidate_state_checks = $statesToRun * $candidates.Count
    literal_states_per_second_wall = $(if ($totalWatch.Elapsed.TotalSeconds -gt 0) { $statesToRun / $totalWatch.Elapsed.TotalSeconds } else { 0 })
    candidate_state_checks_per_second_wall = $(if ($totalWatch.Elapsed.TotalSeconds -gt 0) { ($statesToRun * $candidates.Count) / $totalWatch.Elapsed.TotalSeconds } else { 0 })
    chunks = $chunks
    cpu_chunks = $cpuChunks
    ordered_solutions = $orderedSolutions
    candidates = $candidateSummaries
}

$summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
$summary | ConvertTo-Json -Depth 12
