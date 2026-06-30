param(
    [string]$GpuExePath = ".\enigma_cuda_prefix_filter.exe",
    [string]$CpuExePath = ".\enigma_m3_search_fast.exe",
    [string]$ReaderPlaintextsPath = ".\story_clue_reader_plaintexts_14_only.txt",
    [string]$GordonPlaintextsPath = ".\story_clue_gordon_plaintexts_14_only.txt",
    [string]$Tier = "2",
    [UInt64]$StartIndex = 0,
    [UInt64]$ChunkClasses = 10000000,
    [int]$MaxChunksPerTarget = 0,
    [int]$MaxCandidateAttemptsPerPair = 0,
    [int]$CpuThreads = 8,
    [UInt64]$GpuSurvivorCap = 10000,
    [int]$MaxResultsPerTarget = 1,
    [string]$WorkDir = ".\phrase_pair_first",
    [string]$SummaryPath = ".\phrase_pair_first_summary.json",
    [string]$GeneratedTargetsPath = ".\story_clue_generated_14_only_latest.json",
    [string]$ValidationReportPath = ".\mixed_length_validation_latest.json",
    [switch]$SkipValidation,
    [switch]$SkipGenerate,
    [switch]$GpuCoreCache,
    [switch]$NoGpuCoreCache
)

$ErrorActionPreference = "Stop"
$useGpuCoreCache = -not [bool]$NoGpuCoreCache

function Read-JsonFile {
    param([Parameter(Mandatory=$true)] [string]$Path)
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Normalize-Letters {
    param([Parameter(Mandatory=$true)] [string]$Text)
    return ($Text.ToUpperInvariant() -replace '[^A-Z]', '')
}

function Get-SamePositionLetters {
    param(
        [Parameter(Mandatory=$true)] [string]$Plaintext,
        [Parameter(Mandatory=$true)] [string]$Ciphertext
    )

    $plain = Normalize-Letters $Plaintext
    $cipher = Normalize-Letters $Ciphertext
    if ($plain.Length -ne $cipher.Length) {
        throw "plaintext/ciphertext length mismatch: $plain / $cipher"
    }

    $same = @()
    for ($i = 0; $i -lt $plain.Length; $i++) {
        if ($plain[$i] -eq $cipher[$i]) {
            $same += [pscustomobject]@{ position = $i + 1; letter = [string]$plain[$i] }
        }
    }
    return @($same)
}

function Get-FullBehaviorClassTotal {
    param([Parameter(Mandatory=$true)] [string]$Tier)
    $rotorOrders = if ($Tier -eq "1") { 1 } else { 60 }
    return [UInt64]($rotorOrders * 2 * [Math]::Pow(26, 5))
}

function Invoke-ProcessChecked {
    param(
        [Parameter(Mandatory=$true)] [string]$FilePath,
        [Parameter(Mandatory=$true)] [string[]]$ArgumentList,
        [Parameter(Mandatory=$true)] [string]$WorkingDirectory,
        [Parameter(Mandatory=$true)] [string]$StdoutPath,
        [Parameter(Mandatory=$true)] [string]$StderrPath,
        [Parameter(Mandatory=$true)] [string]$Label
    )

    $watch = [Diagnostics.Stopwatch]::StartNew()
    $proc = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WorkingDirectory $WorkingDirectory -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath -WindowStyle Hidden -PassThru
    $proc.WaitForExit()
    $proc.Refresh()
    $watch.Stop()
    if ($null -ne $proc.ExitCode -and $proc.ExitCode -ne 0) {
        $tail = if (Test-Path -LiteralPath $StderrPath) { Get-Content -LiteralPath $StderrPath -Tail 12 } else { @() }
        throw "$Label failed with exit code $($proc.ExitCode): $($tail -join ' | ')"
    }
    return $watch.Elapsed.TotalSeconds
}

if ($Tier -ne "1" -and $Tier -ne "2") {
    throw "Tier must be 1 or 2"
}

$started = Get-Date
$watch = [Diagnostics.Stopwatch]::StartNew()
$repoDir = (Get-Location).Path
$gpuExe = (Resolve-Path -LiteralPath $GpuExePath).Path
$cpuExe = (Resolve-Path -LiteralPath $CpuExePath).Path
$readerPath = (Resolve-Path -LiteralPath $ReaderPlaintextsPath).Path
$gordonPath = (Resolve-Path -LiteralPath $GordonPlaintextsPath).Path
$fullClasses = Get-FullBehaviorClassTotal -Tier $Tier

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$workFullPath = (Resolve-Path -LiteralPath $WorkDir).Path

$validation = $null
if (-not $SkipValidation) {
    & $cpuExe --mixed-length-validation --output $ValidationReportPath
    if ($LASTEXITCODE -ne 0) {
        throw "mixed-length validation failed; see $ValidationReportPath"
    }
    $validation = Read-JsonFile -Path $ValidationReportPath
}

if (-not $SkipGenerate) {
    & $cpuExe --generate-mixed-reader-candidates --reader-plaintexts-file $readerPath --gordon-plaintexts-file $gordonPath --output $GeneratedTargetsPath
    if ($LASTEXITCODE -ne 0) {
        throw "mixed reader candidate generation failed"
    }
}

$generated = Read-JsonFile -Path $GeneratedTargetsPath
$readerCandidates = @($generated.reader_candidates)
$gordonTargets = @($generated.gordon_targets)

$viableTargets = @()
$sameLengthTargets = @()
$skippedImpossibleTargets = @()
$targetId = 1
foreach ($reader in $readerCandidates) {
    foreach ($gordon in $gordonTargets) {
        if ([int]$reader.normalized_length -ne [int]$gordon.normalized_length) {
            continue
        }
        $same = @(Get-SamePositionLetters -Plaintext $gordon.plaintext -Ciphertext $reader.ciphertext)
        $target = [pscustomobject]@{
            id = $targetId
            length = [int]$reader.normalized_length
            reader_rank = [int]$reader.reader_rank
            reader_plaintext_rank = [int]$reader.reader_plaintext_rank
            reader_generated_rank = [int]$reader.reader_generated_rank
            start_ring_rank = [int]$reader.start_ring_rank
            plugboard_rank = [int]$reader.plugboard_rank
            gordon_rank = [int]$gordon.rank
            reader_plaintext = $reader.reader_plaintext
            reader_start = $reader.start
            reader_rings = $reader.rings
            reader_active_pairs = $reader.active_pairs
            reader_ciphertext = $reader.ciphertext
            gordon_plaintext = $gordon.plaintext
            impossible_same_position_count = [int]$same.Count
        }
        $targetId++
        $sameLengthTargets += $target
        if ($same.Count -gt 0) {
            $skippedImpossibleTargets += $target
        } else {
            $viableTargets += $target
        }
    }
}

$pairSummaries = @()
$positivePairs = @()
$totalGpuWall = 0.0
$totalCpuWall = 0.0
$totalChecks = [UInt64]0
$totalCandidatesAttempted = 0
$totalChunksAttempted = 0

$gordonOrdered = @($gordonTargets | Sort-Object rank)
foreach ($gordon in $gordonOrdered) {
    $gordonDir = Join-Path $workFullPath ("gordon_{0:D3}" -f [int]$gordon.rank)
    New-Item -ItemType Directory -Force -Path $gordonDir | Out-Null
    $readerOrdered = @($generated.reader_plaintexts | Where-Object { [int]$_.normalized_length -eq [int]$gordon.normalized_length } | Sort-Object rank)
    foreach ($readerPlain in $readerOrdered) {
        $pairDir = Join-Path $gordonDir ("reader_{0:D3}" -f [int]$readerPlain.rank)
        New-Item -ItemType Directory -Force -Path $pairDir | Out-Null
        $pairTargets = @($viableTargets |
            Where-Object { [int]$_.gordon_rank -eq [int]$gordon.rank -and [int]$_.reader_plaintext_rank -eq [int]$readerPlain.rank } |
            Sort-Object reader_generated_rank)
        if ($MaxCandidateAttemptsPerPair -gt 0) {
            $pairTargets = @($pairTargets | Select-Object -First $MaxCandidateAttemptsPerPair)
        }
        $pairTargetById = @{}
        foreach ($target in $pairTargets) {
            $pairTargetById[[string]$target.id] = $target
        }

        $found = $false
        $status = if ($pairTargets.Count -eq 0) { "no_viable_targets" } else { "not_found_in_limit" }
        $attemptedChunks = 0
        $pairGpuWall = 0.0
        $pairCpuWall = 0.0
        $pairChecks = [UInt64]0
        $winningTarget = $null
        $winningCpuOutput = $null
        $lastGpuOutput = $null

        if ($pairTargets.Count -gt 0) {
            $chunkStart = $StartIndex
            while ($chunkStart -lt $fullClasses) {
                if ($MaxChunksPerTarget -gt 0 -and $attemptedChunks -ge $MaxChunksPerTarget) {
                break
            }
                $states = [UInt64][Math]::Min([double]$ChunkClasses, [double]($fullClasses - $chunkStart))
                $chunkDir = Join-Path $pairDir ("chunk_{0:D4}" -f ($attemptedChunks + 1))
                New-Item -ItemType Directory -Force -Path $chunkDir | Out-Null
                $candidateFile = Join-Path $chunkDir "targets.tsv"
                $candidateLines = foreach ($target in $pairTargets) {
                    "{0}`treader_{1:D4}_gordon_{2:D4}`t{3}" -f $target.id, $target.reader_rank, $target.gordon_rank, $target.reader_ciphertext
                }
                $candidateLines | Set-Content -LiteralPath $candidateFile -Encoding ASCII

                $gpuOutput = Join-Path $chunkDir "gpu_prefix_results.json"
                $gpuStdout = Join-Path $chunkDir "gpu_prefix.out.txt"
                $gpuStderr = Join-Path $chunkDir "gpu_prefix.err.txt"
                $gpuArgs = @(
                    "--tier", $Tier,
                    "--plaintext", $pairTargets[0].gordon_plaintext,
                    "--candidate-file", $candidateFile,
                    "--behavior-direct",
                    "--start-index", "$chunkStart",
                    "--max-states", "$states",
                    "--prefix-len", "$($pairTargets[0].length)",
                    "--survivor-dir", $chunkDir,
                    "--survivor-cap", "$GpuSurvivorCap",
                    "--output", $gpuOutput
                )
                if ($useGpuCoreCache) {
                    $gpuArgs += "--gpu-core-cache"
                } else {
                    $gpuArgs += "--no-gpu-core-cache"
                }
                $gpuWall = Invoke-ProcessChecked -FilePath $gpuExe -ArgumentList $gpuArgs -WorkingDirectory $repoDir -StdoutPath $gpuStdout -StderrPath $gpuStderr -Label "GPU phrase pair $($readerPlain.plaintext) => $($gordon.plaintext)"
                $pairGpuWall += $gpuWall
                $totalGpuWall += $gpuWall
                $chunkChecks = [UInt64]$states * [UInt64]$pairTargets.Count
                $pairChecks += $chunkChecks
                $totalChecks += $chunkChecks
                $attemptedChunks++
                $totalChunksAttempted++
                $totalCandidatesAttempted += $pairTargets.Count
                $lastGpuOutput = $gpuOutput

                $gpu = Read-JsonFile -Path $gpuOutput
                foreach ($gpuCandidate in @($gpu.candidates)) {
                    $target = $pairTargetById[[string]$gpuCandidate.id]
                    if ($null -eq $target) {
                        throw "GPU output referenced unknown target id $($gpuCandidate.id)"
                    }
                    if ([bool]$gpuCandidate.survivor_overflow) {
                        throw "GPU survivor cap overflow for target $($target.id): survivors=$($gpuCandidate.survivors) cap=$GpuSurvivorCap"
                    }
                    if ([UInt64]$gpuCandidate.survivors -le 0) {
                        continue
                    }
                    $survivorPath = Join-Path $chunkDir ("candidate_{0}_survivors.bin" -f $gpuCandidate.id)
                    if (-not (Test-Path -LiteralPath $survivorPath)) {
                        throw "expected survivor file does not exist: $survivorPath"
                    }
                    $verifyDir = Join-Path $chunkDir ("verify_candidate_{0}" -f $target.id)
                    New-Item -ItemType Directory -Force -Path $verifyDir | Out-Null
                    $cpuOutput = Join-Path $verifyDir "cpu_verify.json"
                    $cpuStdout = Join-Path $verifyDir "cpu_verify.out.txt"
                    $cpuStderr = Join-Path $verifyDir "cpu_verify.err.txt"
                    $cpuArgs = @(
                        "--tier", $Tier,
                        "--plaintext", $target.gordon_plaintext,
                        "--ciphertext", $target.reader_ciphertext,
                        "--behavior-class-list-binary", $survivorPath,
                        "--threads", "$CpuThreads",
                        "--progress-seconds", "0",
                        "--max-results", "$MaxResultsPerTarget",
                        "--skip-initial-tests",
                        "--output", $cpuOutput
                    )
                    $cpuWall = Invoke-ProcessChecked -FilePath $cpuExe -ArgumentList $cpuArgs -WorkingDirectory $repoDir -StdoutPath $cpuStdout -StderrPath $cpuStderr -Label "CPU phrase pair target $($target.id)"
                    $pairCpuWall += $cpuWall
                    $totalCpuWall += $cpuWall
                    $cpu = Read-JsonFile -Path $cpuOutput
                    if ([int]$cpu.result_count -gt 0) {
                        $found = $true
                        $status = "found"
                        $winningTarget = $target
                        $winningCpuOutput = $cpuOutput
                        break
                    }
                }
                if ($found) {
                    break
                }
                $chunkStart += $states
            }
        }

        if (-not $found -and $pairTargets.Count -gt 0 -and
            ($MaxChunksPerTarget -le 0) -and ($chunkStart -ge $fullClasses)) {
            $status = "exhausted_not_found"
        }

        $pairSummary = [pscustomobject]@{
            reader_plaintext_rank = [int]$readerPlain.rank
            reader_plaintext = $readerPlain.plaintext
            gordon_rank = [int]$gordon.rank
            gordon_plaintext = $gordon.plaintext
            status = $status
            found = $found
            viable_generated_targets = $pairTargets.Count
            attempted_generated_targets = $pairTargets.Count
            attempted_chunks = $attemptedChunks
            behavior_classes_checked = $pairChecks
            gpu_wall_seconds = $pairGpuWall
            cpu_verify_wall_seconds = $pairCpuWall
            winning_target_id = $(if ($null -ne $winningTarget) { [int]$winningTarget.id } else { $null })
            winning_reader_start = $(if ($null -ne $winningTarget) { $winningTarget.reader_start } else { $null })
            winning_reader_rings = $(if ($null -ne $winningTarget) { $winningTarget.reader_rings } else { $null })
            winning_reader_active_pairs = $(if ($null -ne $winningTarget) { $winningTarget.reader_active_pairs } else { $null })
            winning_reader_ciphertext = $(if ($null -ne $winningTarget) { $winningTarget.reader_ciphertext } else { $null })
            cpu_output = $winningCpuOutput
            last_gpu_output = $lastGpuOutput
        }
        $pairSummaries += $pairSummary
        if ($found) {
            $positivePairs += $pairSummary
            Write-Host ("FOUND {0} => {1} after testing {2} generated target(s) across {3} chunk(s)" -f $readerPlain.plaintext, $gordon.plaintext, $pairTargets.Count, $attemptedChunks)
        } else {
            Write-Host ("MISS/LIMIT {0} => {1}: {2} after testing {3} generated target(s) across {4} chunk(s)" -f $readerPlain.plaintext, $gordon.plaintext, $status, $pairTargets.Count, $attemptedChunks)
        }
    }
}

$watch.Stop()
$finished = Get-Date
$rate = if ($totalGpuWall -gt 0) { $totalChecks / $totalGpuWall } else { 0 }
$summaryObject = [pscustomobject]@{
    mode = "PhrasePairFirstGpuBehaviorPrefix"
    tier = $Tier
    started = $started.ToString("o")
    finished = $finished.ToString("o")
    wall_elapsed_seconds = $watch.Elapsed.TotalSeconds
    validation_report = $(if ($null -ne $validation) { $ValidationReportPath } else { $null })
    validation_passed = $(if ($null -ne $validation) { [bool]$validation.passed } else { $null })
    generated_targets = $GeneratedTargetsPath
    reader_plaintext_file = $readerPath
    gordon_plaintext_file = $gordonPath
    full_behavior_classes_per_target = $fullClasses
    start_index = $StartIndex
    chunk_classes = $ChunkClasses
    max_chunks_per_target = $MaxChunksPerTarget
    max_candidate_attempts_per_pair = $MaxCandidateAttemptsPerPair
    gpu_core_cache = [bool]$useGpuCoreCache
    gpu_survivor_cap = $GpuSurvivorCap
    total_phrase_pairs = $pairSummaries.Count
    found_phrase_pairs = $positivePairs.Count
    total_gpu_behavior_checks = $totalChecks
    total_gpu_wall_seconds = $totalGpuWall
    total_cpu_verify_wall_seconds = $totalCpuWall
    aggregate_gpu_behavior_checks_per_second = $rate
    total_generated_targets_attempted = $totalCandidatesAttempted
    total_chunks_attempted = $totalChunksAttempted
    positive_phrase_pairs = @($positivePairs | Sort-Object gordon_rank, reader_plaintext_rank)
    phrase_pairs = @($pairSummaries | Sort-Object gordon_rank, reader_plaintext_rank)
}

$summaryObject | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8

[pscustomobject]@{
    mode = $summaryObject.mode
    summary_path = $SummaryPath
    validation_passed = $summaryObject.validation_passed
    total_phrase_pairs = $summaryObject.total_phrase_pairs
    found_phrase_pairs = $summaryObject.found_phrase_pairs
    total_gpu_behavior_checks = $summaryObject.total_gpu_behavior_checks
    wall_elapsed_seconds = $summaryObject.wall_elapsed_seconds
    aggregate_gpu_behavior_checks_per_second = $summaryObject.aggregate_gpu_behavior_checks_per_second
} | ConvertTo-Json -Depth 5
