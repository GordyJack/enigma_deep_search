param(
    [string]$GpuExePath = ".\enigma_cuda_prefix_filter.exe",
    [string]$CpuExePath = ".\enigma_m3_search_fast.exe",
    [string]$Tier = "2",
    [UInt64]$StartIndex = 0,
    [UInt64]$MaxClasses = 50000000,
    [int]$PrefixLength = 17,
    [int]$CpuThreads = 8,
    [int]$MaxResultsPerTarget = 2147483647,
    [int]$MaxReaderRank = 0,
    [int]$MaxGordonRank = 0,
    [string]$WorkDir = ".\gpu_behavior_prefix_targets",
    [string]$SummaryPath = ".\gpu_behavior_prefix_targets_summary.json",
    [string]$GeneratedTargetsPath = ".\generated_reader_candidates_96.json",
    [string]$ValidationReportPath = ".\validation_battery_latest.json",
    [switch]$SkipValidation,
    [switch]$SkipGenerate,
    [switch]$SkipCpuVerify,
    [switch]$DirectEmitSurvivors
)

$ErrorActionPreference = "Stop"

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
            $same += [pscustomobject]@{
                position = $i + 1
                letter = [string]$plain[$i]
            }
        }
    }
    return @($same)
}

function ConvertTo-CandidateId {
    param(
        [Parameter(Mandatory=$true)] [int]$ReaderRank,
        [Parameter(Mandatory=$true)] [int]$GordonRank
    )
    return ($ReaderRank * 100) + $GordonRank
}

$started = Get-Date
$watch = [Diagnostics.Stopwatch]::StartNew()

$gpuExe = (Resolve-Path -LiteralPath $GpuExePath).Path
$cpuExe = (Resolve-Path -LiteralPath $CpuExePath).Path

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$workFullPath = (Resolve-Path -LiteralPath $WorkDir).Path

$validation = $null
if (-not $SkipValidation) {
    & $cpuExe --validation-battery --output $ValidationReportPath
    if ($LASTEXITCODE -ne 0) {
        throw "validation battery failed; see $ValidationReportPath"
    }
    $validation = Read-JsonFile -Path $ValidationReportPath
}

if (-not $SkipGenerate) {
    & $cpuExe --generate-reader-candidates --output $GeneratedTargetsPath
    if ($LASTEXITCODE -ne 0) {
        throw "reader candidate generation failed"
    }
}

$generated = Read-JsonFile -Path $GeneratedTargetsPath
$readerCandidates = @($generated.reader_candidates)
$gordonTargets = @($generated.gordon_plaintexts)

if ($readerCandidates.Count -ne 96) {
    throw "expected 96 reader candidates, got $($readerCandidates.Count)"
}
if ($gordonTargets.Count -ne 8) {
    throw "expected 8 Gordon plaintexts, got $($gordonTargets.Count)"
}

if ($MaxReaderRank -gt 0) {
    $readerCandidates = @($readerCandidates | Where-Object { [int]$_.reader_rank -le $MaxReaderRank })
}
if ($MaxGordonRank -gt 0) {
    $gordonTargets = @($gordonTargets | Where-Object { [int]$_.rank -le $MaxGordonRank })
}

$allTargets = foreach ($reader in $readerCandidates) {
    foreach ($gordon in $gordonTargets) {
        $same = @(Get-SamePositionLetters -Plaintext $gordon.plaintext -Ciphertext $reader.ciphertext)
        [pscustomobject]@{
            id = ConvertTo-CandidateId -ReaderRank ([int]$reader.reader_rank) -GordonRank ([int]$gordon.rank)
            reader_rank = [int]$reader.reader_rank
            gordon_rank = [int]$gordon.rank
            reader_start = $reader.start
            reader_rings = $reader.rings
            reader_active_pairs = $reader.active_pairs
            reader_ciphertext = $reader.ciphertext
            gordon_plaintext = $gordon.plaintext
            impossible_same_position_count = [int]$same.Count
            impossible_same_position_letters = $same
        }
    }
}

$allTargets = @($allTargets | Sort-Object reader_rank, gordon_rank)
$skippedImpossibleTargets = @($allTargets | Where-Object { $_.impossible_same_position_count -gt 0 })
$viableTargets = @($allTargets | Where-Object { $_.impossible_same_position_count -eq 0 })
$targetById = @{}
foreach ($target in $viableTargets) {
    $targetById[[string]$target.id] = $target
}

$groupSummaries = @()
$targetSummaries = @()
$orderedSolutions = @()

foreach ($group in @($viableTargets | Group-Object gordon_rank | Sort-Object { [int]$_.Name })) {
    $gordonRank = [int]$group.Name
    $groupTargets = @($group.Group | Sort-Object reader_rank)
    if ($groupTargets.Count -eq 0) {
        continue
    }

    $gordonPlaintext = $groupTargets[0].gordon_plaintext
    $groupDir = Join-Path $workFullPath ("gordon_{0:D2}" -f $gordonRank)
    New-Item -ItemType Directory -Force -Path $groupDir | Out-Null

    $candidateFile = Join-Path $groupDir "viable_targets.tsv"
    $candidateLines = foreach ($target in $groupTargets) {
        "{0}`treader_{1:D3}_gordon_{2:D2}`t{3}" -f $target.id, $target.reader_rank, $target.gordon_rank, $target.reader_ciphertext
    }
    $candidateLines | Set-Content -LiteralPath $candidateFile -Encoding ASCII

    $gpuOutput = Join-Path $groupDir "gpu_prefix_results.json"
    $gpuStdout = Join-Path $groupDir "gpu_prefix.out.txt"
    $gpuStderr = Join-Path $groupDir "gpu_prefix.err.txt"

    $gpuWatch = [Diagnostics.Stopwatch]::StartNew()
    $gpuArgs = @(
        "--tier", $Tier,
        "--plaintext", $gordonPlaintext,
        "--candidate-file", $candidateFile,
        "--behavior-direct",
        "--start-index", "$StartIndex",
        "--max-states", "$MaxClasses",
        "--prefix-len", "$PrefixLength",
        "--output", $gpuOutput
    )
    if ($DirectEmitSurvivors) {
        $gpuArgs += @("--survivor-dir", $groupDir)
    } else {
        $gpuArgs += "--count-only"
    }
    $gpuProc = Start-Process -FilePath $gpuExe -ArgumentList $gpuArgs -WorkingDirectory (Get-Location).Path -RedirectStandardOutput $gpuStdout -RedirectStandardError $gpuStderr -WindowStyle Hidden -PassThru
    $gpuProc.WaitForExit()
    $gpuProc.Refresh()
    $gpuWatch.Stop()
    if ($null -ne $gpuProc.ExitCode -and $gpuProc.ExitCode -ne 0) {
        $tail = if (Test-Path -LiteralPath $gpuStderr) { Get-Content -LiteralPath $gpuStderr -Tail 10 } else { @() }
        throw "GPU prefix group $gordonRank failed: $($tail -join ' | ')"
    }
    if (-not (Test-Path -LiteralPath $gpuOutput)) {
        $tail = if (Test-Path -LiteralPath $gpuStderr) { Get-Content -LiteralPath $gpuStderr -Tail 10 } else { @() }
        throw "GPU prefix group $gordonRank did not produce output: $($tail -join ' | ')"
    }

    $gpu = Read-JsonFile -Path $gpuOutput
    $candidateResults = @($gpu.candidates)
    $groupSurvivors = [UInt64]0
    $groupCpuSeconds = 0.0
    $groupCpuWallSeconds = 0.0
    $groupVerifiedResults = 0

    foreach ($candidate in $candidateResults) {
        $target = $targetById[[string]$candidate.id]
        if ($null -eq $target) {
            throw "GPU output referenced unknown target id $($candidate.id)"
        }

        $survivors = [UInt64]$candidate.survivors
        $groupSurvivors += $survivors
        $cpuOutput = $null
        $cpuStats = $null
        $cpuResultCount = 0
        $cpuWall = 0.0
        $cpuResults = @()
        $survivorPath = $null
        $replayGpuOutput = $null
        $replayGpuWall = 0.0

        if ($survivors -gt 0 -and -not $SkipCpuVerify) {
            if ($DirectEmitSurvivors) {
                $survivorPath = Join-Path $groupDir ("candidate_{0}_survivors.bin" -f $candidate.id)
            } else {
                $replayDir = Join-Path $groupDir ("replay_candidate_{0}" -f $candidate.id)
                New-Item -ItemType Directory -Force -Path $replayDir | Out-Null
                $replayCandidateFile = Join-Path $replayDir "target.tsv"
                ("{0}`treader_{1:D3}_gordon_{2:D2}`t{3}" -f $target.id, $target.reader_rank, $target.gordon_rank, $target.reader_ciphertext) |
                    Set-Content -LiteralPath $replayCandidateFile -Encoding ASCII
                $replayGpuOutput = Join-Path $replayDir "gpu_replay_results.json"
                $replayGpuStdout = Join-Path $replayDir "gpu_replay.out.txt"
                $replayGpuStderr = Join-Path $replayDir "gpu_replay.err.txt"
                $replayArgs = @(
                    "--tier", $Tier,
                    "--plaintext", $target.gordon_plaintext,
                    "--candidate-file", $replayCandidateFile,
                    "--behavior-direct",
                    "--start-index", "$StartIndex",
                    "--max-states", "$MaxClasses",
                    "--prefix-len", "$PrefixLength",
                    "--survivor-dir", $replayDir,
                    "--output", $replayGpuOutput
                )
                $replayWatch = [Diagnostics.Stopwatch]::StartNew()
                $replayProc = Start-Process -FilePath $gpuExe -ArgumentList $replayArgs -WorkingDirectory (Get-Location).Path -RedirectStandardOutput $replayGpuStdout -RedirectStandardError $replayGpuStderr -WindowStyle Hidden -PassThru
                $replayProc.WaitForExit()
                $replayProc.Refresh()
                $replayWatch.Stop()
                $replayGpuWall = $replayWatch.Elapsed.TotalSeconds
                if ($null -ne $replayProc.ExitCode -and $replayProc.ExitCode -ne 0) {
                    $tail = if (Test-Path -LiteralPath $replayGpuStderr) { Get-Content -LiteralPath $replayGpuStderr -Tail 10 } else { @() }
                    throw "GPU replay failed for reader=$($target.reader_rank) gordon=$($target.gordon_rank): $($tail -join ' | ')"
                }
                if (-not (Test-Path -LiteralPath $replayGpuOutput)) {
                    $tail = if (Test-Path -LiteralPath $replayGpuStderr) { Get-Content -LiteralPath $replayGpuStderr -Tail 10 } else { @() }
                    throw "GPU replay did not produce output for reader=$($target.reader_rank) gordon=$($target.gordon_rank): $($tail -join ' | ')"
                }
                $replay = Read-JsonFile -Path $replayGpuOutput
                $replayCandidate = @($replay.candidates)[0]
                if ([UInt64]$replayCandidate.survivors -ne $survivors) {
                    throw "GPU replay survivor count mismatch for reader=$($target.reader_rank) gordon=$($target.gordon_rank): count-only=$survivors replay=$($replayCandidate.survivors)"
                }
                $survivorPath = Join-Path $replayDir ("candidate_{0}_survivors.bin" -f $candidate.id)
            }

            if (-not (Test-Path -LiteralPath $survivorPath)) {
                throw "expected survivor file does not exist: $survivorPath"
            }
            $cpuOutput = Join-Path $groupDir ("reader_{0:D3}_gordon_{1:D2}_cpu_verify.json" -f $target.reader_rank, $target.gordon_rank)
            $cpuStdout = Join-Path $groupDir ("reader_{0:D3}_gordon_{1:D2}_cpu_verify.out.txt" -f $target.reader_rank, $target.gordon_rank)
            $cpuStderr = Join-Path $groupDir ("reader_{0:D3}_gordon_{1:D2}_cpu_verify.err.txt" -f $target.reader_rank, $target.gordon_rank)

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
            $cpuWatch = [Diagnostics.Stopwatch]::StartNew()
            $cpuProc = Start-Process -FilePath $cpuExe -ArgumentList $cpuArgs -WorkingDirectory (Get-Location).Path -RedirectStandardOutput $cpuStdout -RedirectStandardError $cpuStderr -WindowStyle Hidden -PassThru
            $cpuProc.WaitForExit()
            $cpuProc.Refresh()
            $cpuWatch.Stop()
            $cpuWall = $cpuWatch.Elapsed.TotalSeconds
            $groupCpuWallSeconds += $cpuWall
            if ($null -ne $cpuProc.ExitCode -and $cpuProc.ExitCode -ne 0) {
                $tail = if (Test-Path -LiteralPath $cpuStderr) { Get-Content -LiteralPath $cpuStderr -Tail 10 } else { @() }
                throw "CPU verification failed for reader=$($target.reader_rank) gordon=$($target.gordon_rank): $($tail -join ' | ')"
            }
            if (-not (Test-Path -LiteralPath $cpuOutput)) {
                $tail = if (Test-Path -LiteralPath $cpuStderr) { Get-Content -LiteralPath $cpuStderr -Tail 10 } else { @() }
                throw "CPU verification did not produce output for reader=$($target.reader_rank) gordon=$($target.gordon_rank): $($tail -join ' | ')"
            }

            $cpu = Read-JsonFile -Path $cpuOutput
            $cpuStats = @($cpu.tier_stats)[0]
            $cpuResultCount = [int]$cpu.result_count
            $cpuResults = @($cpu.results)
            if ($null -ne $cpuStats) {
                $groupCpuSeconds += [double]$cpuStats.elapsed_seconds
            }
            $groupVerifiedResults += $cpuResultCount
        }

        $targetSummary = [pscustomobject]@{
            id = [int]$candidate.id
            reader_rank = $target.reader_rank
            gordon_rank = $target.gordon_rank
            reader_start = $target.reader_start
            reader_rings = $target.reader_rings
            reader_active_pairs = $target.reader_active_pairs
            reader_ciphertext = $target.reader_ciphertext
            gordon_plaintext = $target.gordon_plaintext
            prefix_len = $PrefixLength
            behavior_classes_checked = [UInt64]$MaxClasses
            gpu_survivors = $survivors
            gpu_kernel_seconds = [double]$candidate.elapsed_seconds
            gpu_classes_per_second = [double]$candidate.states_per_second
            cpu_verify_wall_seconds = $cpuWall
            cpu_verify_solver_seconds = $(if ($null -ne $cpuStats) { [double]$cpuStats.elapsed_seconds } else { 0.0 })
            cpu_verified_result_count = $cpuResultCount
            gpu_replay_wall_seconds = $replayGpuWall
            gpu_replay_output = $replayGpuOutput
            cpu_output = $cpuOutput
            gpu_output = $gpuOutput
            results = $cpuResults
        }
        $targetSummaries += $targetSummary
    }

    $groupSummaries += [pscustomobject]@{
        gordon_rank = $gordonRank
        gordon_plaintext = $gordonPlaintext
        viable_targets = $groupTargets.Count
        prefix_len = $PrefixLength
        behavior_classes_per_target = [UInt64]$MaxClasses
        aggregate_behavior_target_checks = [UInt64]$MaxClasses * [UInt64]$groupTargets.Count
        gpu_wall_seconds = $gpuWatch.Elapsed.TotalSeconds
        gpu_json_wall_seconds = [double]$gpu.wall_elapsed_seconds
        gpu_aggregate_checks_per_second_wall = $(if ($gpuWatch.Elapsed.TotalSeconds -gt 0) { ([UInt64]$MaxClasses * [UInt64]$groupTargets.Count) / $gpuWatch.Elapsed.TotalSeconds } else { 0 })
        gpu_survivors = $groupSurvivors
        gpu_count_only = -not [bool]$DirectEmitSurvivors
        cpu_verify_wall_seconds = $groupCpuWallSeconds
        cpu_verify_solver_seconds = $groupCpuSeconds
        cpu_verified_result_count = $groupVerifiedResults
        candidate_file = $candidateFile
        gpu_output = $gpuOutput
    }
}

foreach ($summary in @($targetSummaries | Sort-Object reader_rank, gordon_rank)) {
    foreach ($result in @($summary.results)) {
        $orderedSolutions += [pscustomobject]@{
            reader_rank = $summary.reader_rank
            gordon_rank = $summary.gordon_rank
            reader_start = $summary.reader_start
            reader_rings = $summary.reader_rings
            reader_active_pairs = $summary.reader_active_pairs
            reader_ciphertext = $summary.reader_ciphertext
            gordon_plaintext = $summary.gordon_plaintext
            reflector = $result.reflector
            rotors_left_to_right = $result.rotors_left_to_right
            start_left_to_right = $result.start_left_to_right
            rings_left_to_right = $result.rings_left_to_right
            plugboard_pairs = $result.plugboard_pairs
            plugboard_pair_count = $result.plugboard_pair_count
            verification_ciphertext = $result.verification_ciphertext
            output = $summary.cpu_output
        }
    }
}

$watch.Stop()
$finished = Get-Date

$totalGpuChecks = [UInt64](($groupSummaries | Measure-Object -Property aggregate_behavior_target_checks -Sum).Sum)
$totalSurvivors = [UInt64](($groupSummaries | Measure-Object -Property gpu_survivors -Sum).Sum)
$totalGpuWall = [double](($groupSummaries | Measure-Object -Property gpu_wall_seconds -Sum).Sum)
$totalCpuWall = [double](($groupSummaries | Measure-Object -Property cpu_verify_wall_seconds -Sum).Sum)
$fullClassTotalPerTarget = [UInt64](60 * 2 * [Math]::Pow(26, 5))
$selectedViableCount = @($viableTargets).Count
$fullSelectedChecks = $fullClassTotalPerTarget * [UInt64]$selectedViableCount
$aggregateRate = if ($totalGpuWall -gt 0) { $totalGpuChecks / $totalGpuWall } else { 0 }

$summaryObject = [pscustomobject]@{
    mode = "GpuBehaviorPrefix"
    tier = $Tier
    prefix_len = $PrefixLength
    started = $started.ToString("o")
    finished = $finished.ToString("o")
    wall_elapsed_seconds = $watch.Elapsed.TotalSeconds
    validation_report = $(if ($null -ne $validation) { $ValidationReportPath } else { $null })
    generated_targets = $GeneratedTargetsPath
    reader_candidate_count_available = [int]$generated.reader_candidate_count
    gordon_plaintext_count_available = [int]$generated.gordon_plaintext_count
    target_pairing_count_available = [int]$generated.target_pairing_count
    target_pairing_count_selected = $allTargets.Count
    target_pairing_count_skipped_impossible = $skippedImpossibleTargets.Count
    target_pairing_count_viable = $selectedViableCount
    start_index = $StartIndex
    behavior_classes_per_target = [UInt64]$MaxClasses
    total_gpu_behavior_target_checks = $totalGpuChecks
    total_gpu_survivors = $totalSurvivors
    total_gpu_wall_seconds = $totalGpuWall
    total_cpu_verify_wall_seconds = $totalCpuWall
    count_only_first = -not [bool]$DirectEmitSurvivors
    aggregate_gpu_behavior_target_checks_per_second = $aggregateRate
    full_behavior_classes_per_target = $fullClassTotalPerTarget
    estimated_full_behavior_target_checks_for_selected = $fullSelectedChecks
    estimated_full_gpu_prefilter_seconds_for_selected = $(if ($aggregateRate -gt 0) { $fullSelectedChecks / $aggregateRate } else { $null })
    cpu_verify_skipped = [bool]$SkipCpuVerify
    ordered_solution_count = @($orderedSolutions).Count
    ordered_solutions = $orderedSolutions
    groups = $groupSummaries
    targets = @($targetSummaries | Sort-Object reader_rank, gordon_rank | Select-Object -Property * -ExcludeProperty results)
    skipped_impossible_target_examples = @($skippedImpossibleTargets | Select-Object -First 20 reader_rank, gordon_rank, reader_ciphertext, gordon_plaintext, impossible_same_position_count, impossible_same_position_letters)
}

$summaryObject | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8

[pscustomobject]@{
    mode = $summaryObject.mode
    summary_path = $SummaryPath
    prefix_len = $PrefixLength
    behavior_classes_per_target = [UInt64]$MaxClasses
    viable_targets = $selectedViableCount
    skipped_impossible = $skippedImpossibleTargets.Count
    total_gpu_behavior_target_checks = $totalGpuChecks
    total_gpu_survivors = $totalSurvivors
    ordered_solution_count = @($orderedSolutions).Count
    wall_elapsed_seconds = $summaryObject.wall_elapsed_seconds
    aggregate_gpu_behavior_target_checks_per_second = $aggregateRate
    estimated_full_prefilter_hours_for_selected = $(if ($aggregateRate -gt 0) { ($fullSelectedChecks / $aggregateRate) / 3600.0 } else { $null })
} | ConvertTo-Json -Depth 5
