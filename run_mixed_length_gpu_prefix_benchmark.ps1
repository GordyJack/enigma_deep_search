param(
    [string]$GpuExePath = ".\enigma_cuda_prefix_filter.exe",
    [string]$CpuExePath = ".\enigma_m3_search_fast.exe",
    [string]$ReaderPlaintextsPath = ".\mixed_benchmark_reader_plaintexts.txt",
    [string]$GordonPlaintextsPath = ".\mixed_benchmark_gordon_plaintexts.txt",
    [string]$Tier = "2",
    [UInt64]$StartIndex = 0,
    [UInt64]$MaxTotalClassesPerLength = 10000000,
    [int]$CpuThreads = 8,
    [int]$MaxResultsPerTarget = 2147483647,
    [string]$WorkDir = ".\mixed_length_gpu_prefix_benchmark",
    [string]$SummaryPath = ".\mixed_length_gpu_prefix_benchmark_summary.json",
    [string]$GeneratedTargetsPath = ".\mixed_generated_benchmark.json",
    [string]$ValidationReportPath = ".\mixed_length_validation_latest.json",
    [switch]$SkipValidation,
    [switch]$SkipGenerate,
    [switch]$SkipCpuVerify
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

function Get-FullBehaviorClassTotal {
    param([Parameter(Mandatory=$true)] [string]$Tier)
    $rotorOrders = if ($Tier -eq "1") { 1 } else { 60 }
    return [UInt64]($rotorOrders * 2 * [Math]::Pow(26, 5))
}

function Invoke-CheckedProcess {
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
    throw "Tier must be 1 or 2 for GPU behavior-prefix benchmarking"
}

$started = Get-Date
$watch = [Diagnostics.Stopwatch]::StartNew()
$repoDir = (Get-Location).Path
$gpuExe = (Resolve-Path -LiteralPath $GpuExePath).Path
$cpuExe = (Resolve-Path -LiteralPath $CpuExePath).Path
$readerPath = (Resolve-Path -LiteralPath $ReaderPlaintextsPath).Path
$gordonPath = (Resolve-Path -LiteralPath $GordonPlaintextsPath).Path

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
$lengthOrder = @($generated.length_stats | ForEach-Object { [int]$_.length })

$sameLengthTargets = @()
$skippedImpossibleTargets = @()
$viableTargets = @()
$targetId = 1
foreach ($reader in $readerCandidates) {
    foreach ($gordon in $gordonTargets) {
        $readerLength = [int]$reader.normalized_length
        $gordonLength = [int]$gordon.normalized_length
        if ($readerLength -ne $gordonLength) {
            continue
        }

        $same = @(Get-SamePositionLetters -Plaintext $gordon.plaintext -Ciphertext $reader.ciphertext)
        $target = [pscustomobject]@{
            id = $targetId
            length = $readerLength
            reader_rank = [int]$reader.reader_rank
            reader_plaintext_rank = [int]$reader.reader_plaintext_rank
            reader_generated_rank = [int]$reader.reader_generated_rank
            start_ring_rank = [int]$reader.start_ring_rank
            plugboard_rank = [int]$reader.plugboard_rank
            gordon_rank = [int]$gordon.rank
            reader_plaintext = $reader.reader_plaintext
            reader_plaintext_original = $reader.reader_plaintext_original
            reader_start = $reader.start
            reader_rings = $reader.rings
            reader_active_pairs = $reader.active_pairs
            reader_ciphertext = $reader.ciphertext
            gordon_plaintext = $gordon.plaintext
            gordon_original = $gordon.original
            impossible_same_position_count = [int]$same.Count
            impossible_same_position_letters = $same
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

$targetById = @{}
foreach ($target in $viableTargets) {
    $targetById[[string]$target.id] = $target
}

$lengthSummaries = @()
$groupSummaries = @()
$targetSummaries = @()
$orderedSolutions = @()
$fullClassesPerTarget = Get-FullBehaviorClassTotal -Tier $Tier

foreach ($length in $lengthOrder) {
    $lengthTargets = @($viableTargets | Where-Object { [int]$_.length -eq $length } | Sort-Object reader_plaintext_rank, reader_generated_rank, gordon_rank)
    $lengthSameTargets = @($sameLengthTargets | Where-Object { [int]$_.length -eq $length })
    $lengthImpossible = @($skippedImpossibleTargets | Where-Object { [int]$_.length -eq $length })
    $readerPlainCount = @($generated.reader_plaintexts | Where-Object { [int]$_.normalized_length -eq $length }).Count
    $gordonPlainCount = @($generated.gordon_targets | Where-Object { [int]$_.normalized_length -eq $length }).Count
    $generatedReaderCount = @($readerCandidates | Where-Object { [int]$_.normalized_length -eq $length }).Count

    if ($lengthTargets.Count -eq 0) {
        $lengthSummaries += [pscustomobject]@{
            length = $length
            reader_plaintext_count = $readerPlainCount
            gordon_plaintext_count = $gordonPlainCount
            generated_reader_ciphertext_count = $generatedReaderCount
            same_length_pairings = $lengthSameTargets.Count
            impossible_pairings_skipped = $lengthImpossible.Count
            viable_pairings = 0
            behavior_classes_per_target = 0
            aggregate_behavior_target_checks = 0
            gpu_wall_seconds = 0.0
            behavior_target_checks_per_second = 0.0
            projected_full_prefilter_seconds = $null
            projected_full_prefilter_hours = $null
            cpu_verified_result_count = 0
        }
        continue
    }

    $classesPerTarget = [UInt64][Math]::Max(1, [Math]::Floor([double]$MaxTotalClassesPerLength / [double]$lengthTargets.Count))
    $lengthDir = Join-Path $workFullPath ("length_{0}" -f $length)
    New-Item -ItemType Directory -Force -Path $lengthDir | Out-Null

    $lengthGpuWall = 0.0
    $lengthCpuWall = 0.0
    $lengthSurvivors = [UInt64]0
    $lengthVerifiedResults = 0

    foreach ($group in @($lengthTargets | Group-Object gordon_rank | Sort-Object { [int]$_.Name })) {
        $gordonRank = [int]$group.Name
        $groupTargets = @($group.Group | Sort-Object reader_plaintext_rank, reader_generated_rank)
        $gordonPlaintext = $groupTargets[0].gordon_plaintext
        $groupDir = Join-Path $lengthDir ("gordon_{0:D3}" -f $gordonRank)
        New-Item -ItemType Directory -Force -Path $groupDir | Out-Null

        $candidateFile = Join-Path $groupDir "viable_targets.tsv"
        $candidateLines = foreach ($target in $groupTargets) {
            "{0}`tlen_{1}_reader_{2:D4}_gordon_{3:D4}`t{4}" -f $target.id, $target.length, $target.reader_rank, $target.gordon_rank, $target.reader_ciphertext
        }
        $candidateLines | Set-Content -LiteralPath $candidateFile -Encoding ASCII

        $gpuOutput = Join-Path $groupDir "gpu_prefix_results.json"
        $gpuStdout = Join-Path $groupDir "gpu_prefix.out.txt"
        $gpuStderr = Join-Path $groupDir "gpu_prefix.err.txt"
        $gpuArgs = @(
            "--tier", $Tier,
            "--plaintext", $gordonPlaintext,
            "--candidate-file", $candidateFile,
            "--behavior-direct",
            "--start-index", "$StartIndex",
            "--max-states", "$classesPerTarget",
            "--prefix-len", "$length",
            "--count-only",
            "--output", $gpuOutput
        )
        $gpuWall = Invoke-CheckedProcess -FilePath $gpuExe -ArgumentList $gpuArgs -WorkingDirectory $repoDir -StdoutPath $gpuStdout -StderrPath $gpuStderr -Label "GPU length $length Gordon rank $gordonRank"
        $lengthGpuWall += $gpuWall
        $gpu = Read-JsonFile -Path $gpuOutput
        $candidateResults = @($gpu.candidates)
        $groupSurvivors = [UInt64]0
        $groupCpuWall = 0.0
        $groupVerified = 0

        foreach ($candidate in $candidateResults) {
            $target = $targetById[[string]$candidate.id]
            if ($null -eq $target) {
                throw "GPU output referenced unknown target id $($candidate.id)"
            }

            $survivors = [UInt64]$candidate.survivors
            $groupSurvivors += $survivors
            $lengthSurvivors += $survivors
            $cpuOutput = $null
            $cpuWall = 0.0
            $cpuResults = @()
            $cpuResultCount = 0
            $replayGpuOutput = $null
            $replayGpuWall = 0.0

            if ($survivors -gt 0 -and -not $SkipCpuVerify) {
                $replayDir = Join-Path $groupDir ("replay_candidate_{0}" -f $candidate.id)
                New-Item -ItemType Directory -Force -Path $replayDir | Out-Null
                $replayCandidateFile = Join-Path $replayDir "target.tsv"
                ("{0}`tlen_{1}_reader_{2:D4}_gordon_{3:D4}`t{4}" -f $target.id, $target.length, $target.reader_rank, $target.gordon_rank, $target.reader_ciphertext) |
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
                    "--max-states", "$classesPerTarget",
                    "--prefix-len", "$length",
                    "--survivor-dir", $replayDir,
                    "--output", $replayGpuOutput
                )
                $replayGpuWall = Invoke-CheckedProcess -FilePath $gpuExe -ArgumentList $replayArgs -WorkingDirectory $repoDir -StdoutPath $replayGpuStdout -StderrPath $replayGpuStderr -Label "GPU replay target $($target.id)"
                $survivorPath = Join-Path $replayDir ("candidate_{0}_survivors.bin" -f $candidate.id)
                if (-not (Test-Path -LiteralPath $survivorPath)) {
                    throw "expected survivor file does not exist: $survivorPath"
                }

                $cpuOutput = Join-Path $replayDir "cpu_verify.json"
                $cpuStdout = Join-Path $replayDir "cpu_verify.out.txt"
                $cpuStderr = Join-Path $replayDir "cpu_verify.err.txt"
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
                $cpuWall = Invoke-CheckedProcess -FilePath $cpuExe -ArgumentList $cpuArgs -WorkingDirectory $repoDir -StdoutPath $cpuStdout -StderrPath $cpuStderr -Label "CPU verification target $($target.id)"
                $lengthCpuWall += $cpuWall
                $groupCpuWall += $cpuWall
                $cpu = Read-JsonFile -Path $cpuOutput
                $cpuResults = @($cpu.results)
                $cpuResultCount = [int]$cpu.result_count
                $groupVerified += $cpuResultCount
                $lengthVerifiedResults += $cpuResultCount
            }

            $targetSummary = [pscustomobject]@{
                id = [int]$candidate.id
                length = $target.length
                reader_rank = $target.reader_rank
                reader_plaintext_rank = $target.reader_plaintext_rank
                reader_generated_rank = $target.reader_generated_rank
                gordon_rank = $target.gordon_rank
                reader_plaintext = $target.reader_plaintext
                reader_start = $target.reader_start
                reader_rings = $target.reader_rings
                reader_active_pairs = $target.reader_active_pairs
                reader_ciphertext = $target.reader_ciphertext
                gordon_plaintext = $target.gordon_plaintext
                behavior_classes_checked = $classesPerTarget
                gpu_survivors = $survivors
                gpu_kernel_seconds = [double]$candidate.elapsed_seconds
                gpu_classes_per_second = [double]$candidate.states_per_second
                cpu_verify_wall_seconds = $cpuWall
                cpu_verified_result_count = $cpuResultCount
                gpu_replay_wall_seconds = $replayGpuWall
                gpu_replay_output = $replayGpuOutput
                cpu_output = $cpuOutput
                gpu_output = $gpuOutput
                results = $cpuResults
            }
            $targetSummaries += $targetSummary
        }

        $groupChecks = [UInt64]$classesPerTarget * [UInt64]$groupTargets.Count
        $groupSummaries += [pscustomobject]@{
            length = $length
            gordon_rank = $gordonRank
            gordon_plaintext = $gordonPlaintext
            viable_targets = $groupTargets.Count
            behavior_classes_per_target = $classesPerTarget
            aggregate_behavior_target_checks = $groupChecks
            gpu_wall_seconds = $gpuWall
            gpu_json_wall_seconds = [double]$gpu.wall_elapsed_seconds
            gpu_aggregate_checks_per_second_wall = $(if ($gpuWall -gt 0) { $groupChecks / $gpuWall } else { 0 })
            gpu_survivors = $groupSurvivors
            cpu_verify_wall_seconds = $groupCpuWall
            cpu_verified_result_count = $groupVerified
            candidate_file = $candidateFile
            gpu_output = $gpuOutput
        }
    }

    $lengthChecks = [UInt64]$classesPerTarget * [UInt64]$lengthTargets.Count
    $lengthRate = if ($lengthGpuWall -gt 0) { $lengthChecks / $lengthGpuWall } else { 0 }
    $projectedSeconds = if ($lengthRate -gt 0) { ([double]$fullClassesPerTarget * [double]$lengthTargets.Count) / $lengthRate } else { $null }
    $lengthSummaries += [pscustomobject]@{
        length = $length
        reader_plaintext_count = $readerPlainCount
        gordon_plaintext_count = $gordonPlainCount
        generated_reader_ciphertext_count = $generatedReaderCount
        same_length_pairings = $lengthSameTargets.Count
        impossible_pairings_skipped = $lengthImpossible.Count
        viable_pairings = $lengthTargets.Count
        behavior_classes_per_target = $classesPerTarget
        aggregate_behavior_target_checks = $lengthChecks
        gpu_wall_seconds = $lengthGpuWall
        behavior_target_checks_per_second = $lengthRate
        projected_full_prefilter_seconds = $projectedSeconds
        projected_full_prefilter_hours = $(if ($null -ne $projectedSeconds) { $projectedSeconds / 3600.0 } else { $null })
        gpu_survivors = $lengthSurvivors
        cpu_verify_wall_seconds = $lengthCpuWall
        cpu_verified_result_count = $lengthVerifiedResults
    }
}

foreach ($summary in @($targetSummaries | Sort-Object reader_plaintext_rank, reader_generated_rank, gordon_rank)) {
    foreach ($result in @($summary.results)) {
        $orderedSolutions += [pscustomobject]@{
            length = $summary.length
            reader_plaintext_rank = $summary.reader_plaintext_rank
            reader_generated_rank = $summary.reader_generated_rank
            gordon_rank = $summary.gordon_rank
            reader_rank = $summary.reader_rank
            reader_plaintext = $summary.reader_plaintext
            reader_start = $summary.reader_start
            reader_rings = $summary.reader_rings
            reader_active_pairs = $summary.reader_active_pairs
            reader_ciphertext = $summary.reader_ciphertext
            gordon_plaintext = $summary.gordon_plaintext
            tier = $result.tier
            reflector = $result.reflector
            rotors_left_to_right = $result.rotors_left_to_right
            rotors_text = ($result.rotors_left_to_right -join "-")
            start_left_to_right = $result.start_left_to_right
            rings_left_to_right = $result.rings_left_to_right
            plugboard_pairs = $result.plugboard_pairs
            plugboard_pair_count = $result.plugboard_pair_count
            plugboard_text = ($result.plugboard_pairs -join " ")
            verification_ciphertext = $result.verification_ciphertext
            output = $summary.cpu_output
        }
    }
}
$orderedSolutions = @($orderedSolutions | Sort-Object reader_plaintext_rank, reader_generated_rank, gordon_rank, tier, reflector, rotors_text, start_left_to_right, rings_left_to_right, plugboard_pair_count, plugboard_text)

$watch.Stop()
$finished = Get-Date
$totalChecks = [UInt64](($lengthSummaries | Measure-Object -Property aggregate_behavior_target_checks -Sum).Sum)
$totalGpuWall = [double](($lengthSummaries | Measure-Object -Property gpu_wall_seconds -Sum).Sum)
$totalCpuWall = [double](($lengthSummaries | Measure-Object -Property cpu_verify_wall_seconds -Sum).Sum)
$totalProjectedSeconds = ($lengthSummaries | Where-Object { $null -ne $_.projected_full_prefilter_seconds } | Measure-Object -Property projected_full_prefilter_seconds -Sum).Sum
$aggregateRate = if ($totalGpuWall -gt 0) { $totalChecks / $totalGpuWall } else { 0 }

$summaryObject = [pscustomobject]@{
    mode = "MixedLengthGpuBehaviorPrefixBenchmark"
    tier = $Tier
    started = $started.ToString("o")
    finished = $finished.ToString("o")
    wall_elapsed_seconds = $watch.Elapsed.TotalSeconds
    validation_report = $(if ($null -ne $validation) { $ValidationReportPath } else { $null })
    validation_passed = $(if ($null -ne $validation) { [bool]$validation.passed } else { $null })
    generated_targets = $GeneratedTargetsPath
    reader_plaintext_file = $readerPath
    gordon_plaintext_file = $gordonPath
    reader_raw_count = [int]$generated.reader_raw_count
    gordon_raw_count = [int]$generated.gordon_raw_count
    reader_accepted_count = [int]$generated.reader_accepted_count
    gordon_accepted_count = [int]$generated.gordon_accepted_count
    reader_generated_candidate_count = [int]$generated.reader_generated_candidate_count
    same_length_pairing_count = @($sameLengthTargets).Count
    impossible_pairings_skipped = @($skippedImpossibleTargets).Count
    viable_pairing_count = @($viableTargets).Count
    start_index = $StartIndex
    max_total_behavior_classes_per_length = $MaxTotalClassesPerLength
    full_behavior_classes_per_target = $fullClassesPerTarget
    cpu_threads = $CpuThreads
    cpu_verify_skipped = [bool]$SkipCpuVerify
    total_gpu_behavior_target_checks = $totalChecks
    total_gpu_wall_seconds = $totalGpuWall
    total_cpu_verify_wall_seconds = $totalCpuWall
    aggregate_gpu_behavior_target_checks_per_second = $aggregateRate
    projected_full_prefilter_seconds_combined = $totalProjectedSeconds
    projected_full_prefilter_hours_combined = $(if ($null -ne $totalProjectedSeconds) { $totalProjectedSeconds / 3600.0 } else { $null })
    ordered_solution_count = @($orderedSolutions).Count
    best_result_overall = @($orderedSolutions | Select-Object -First 1)
    ordered_solutions = $orderedSolutions
    length_stats = $lengthSummaries
    groups = $groupSummaries
    targets = @($targetSummaries | Sort-Object length, reader_plaintext_rank, reader_generated_rank, gordon_rank | Select-Object -Property * -ExcludeProperty results)
    skipped_impossible_target_examples = @($skippedImpossibleTargets | Select-Object -First 20 length, reader_plaintext_rank, reader_generated_rank, gordon_rank, reader_ciphertext, gordon_plaintext, impossible_same_position_count, impossible_same_position_letters)
}

$summaryObject | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8

[pscustomobject]@{
    mode = $summaryObject.mode
    summary_path = $SummaryPath
    validation_passed = $summaryObject.validation_passed
    max_total_behavior_classes_per_length = $MaxTotalClassesPerLength
    viable_pairings = $summaryObject.viable_pairing_count
    total_gpu_behavior_target_checks = $totalChecks
    wall_elapsed_seconds = $summaryObject.wall_elapsed_seconds
    aggregate_gpu_behavior_target_checks_per_second = $aggregateRate
    projected_full_prefilter_hours_combined = $summaryObject.projected_full_prefilter_hours_combined
    ordered_solution_count = @($orderedSolutions).Count
} | ConvertTo-Json -Depth 6
