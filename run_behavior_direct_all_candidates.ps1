param(
    [string]$ExePath = ".\enigma_m3_search_fast.exe",
    [ValidateSet("EarlyStop", "Full", "ValidationOnly")]
    [string]$Mode = "EarlyStop",
    [string]$Tier = "2",
    [UInt64]$StartIndex = 0,
    [UInt64]$MaxStates = 0,
    [int]$ThreadsPerTarget = 4,
    [int]$MaxConcurrentTargets = 0,
    [int]$ProgressSeconds = 30,
    [int]$MaxResultsPerTarget = 2147483647,
    [int]$MaxReaderRank = 0,
    [int]$MaxGordonRank = 0,
    [string]$WorkDir = ".\behavior_direct_targets",
    [string]$SummaryPath = ".\behavior_direct_targets_summary.json",
    [string]$GeneratedTargetsPath = ".\generated_reader_candidates_96.json",
    [string]$ValidationReportPath = ".\validation_battery_latest.json",
    [switch]$SkipValidation,
    [switch]$SkipGenerate
)

$ErrorActionPreference = "Stop"

function Read-JsonFile {
    param([Parameter(Mandatory=$true)] [string]$Path)
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Get-SamePositionLetters {
    param(
        [Parameter(Mandatory=$true)] [string]$Plaintext,
        [Parameter(Mandatory=$true)] [string]$Ciphertext
    )

    $plain = ($Plaintext.ToUpperInvariant() -replace '[^A-Z]', '')
    $cipher = ($Ciphertext.ToUpperInvariant() -replace '[^A-Z]', '')
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

function Start-TargetSearch {
    param(
        [Parameter(Mandatory=$true)] [object]$Target,
        [Parameter(Mandatory=$true)] [string]$BatchDir,
        [Parameter(Mandatory=$true)] [string]$ExeFullPath
    )

    $prefix = "reader_{0:D3}_gordon_{1:D2}" -f [int]$Target.reader_rank, [int]$Target.gordon_rank
    $jsonPath = Join-Path $BatchDir ($prefix + ".json")
    $stdout = Join-Path $BatchDir ($prefix + ".out.txt")
    $stderr = Join-Path $BatchDir ($prefix + ".err.txt")
    $args = @(
        "--tier", $Tier,
        "--plaintext", $Target.gordon_plaintext,
        "--ciphertext", $Target.reader_ciphertext,
        "--threads", "$ThreadsPerTarget",
        "--start-index", "$StartIndex",
        "--progress-seconds", "$ProgressSeconds",
        "--max-results", "$MaxResultsPerTarget",
        "--skip-initial-tests",
        "--behavior-direct",
        "--output", $jsonPath
    )
    if ($MaxStates -gt 0) {
        $args += @("--max-states", "$MaxStates")
    }

    $proc = Start-Process -FilePath $ExeFullPath -ArgumentList $args -WorkingDirectory (Get-Location).Path -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    [pscustomobject]@{
        process = $proc
        target = $Target
        output = $jsonPath
        stdout = $stdout
        stderr = $stderr
    }
}

function Read-TargetSearchSummary {
    param(
        [Parameter(Mandatory=$true)] [object]$Item
    )

    if (-not (Test-Path -LiteralPath $Item.output)) {
        $tail = if (Test-Path -LiteralPath $Item.stderr) { Get-Content -LiteralPath $Item.stderr -Tail 5 } else { @() }
        throw "missing target output for reader=$($Item.target.reader_rank) gordon=$($Item.target.gordon_rank): $($tail -join ' | ')"
    }
    $parsed = Read-JsonFile -Path $Item.output
    $tierStats = @($parsed.tier_stats)[0]
    [pscustomobject]@{
        reader_rank = [int]$Item.target.reader_rank
        gordon_rank = [int]$Item.target.gordon_rank
        reader_start = $Item.target.reader_start
        reader_rings = $Item.target.reader_rings
        reader_active_pairs = $Item.target.reader_active_pairs
        reader_ciphertext = $Item.target.reader_ciphertext
        gordon_plaintext = $Item.target.gordon_plaintext
        result_count = [int]$parsed.result_count
        behavior_classes_checked = [UInt64]$parsed.states_checked
        literal_states_represented = [UInt64]$parsed.states_checked * 26
        elapsed_seconds_reported = [double]$tierStats.elapsed_seconds
        stage10_pass = [UInt64]$tierStats.stage10_pass
        full_solves = [UInt64]$tierStats.full_solves
        output = $Item.output
        results = @($parsed.results)
    }
}

function Invoke-TargetPool {
    param(
        [Parameter(Mandatory=$true)] [object[]]$Targets,
        [Parameter(Mandatory=$true)] [string]$BatchDir,
        [Parameter(Mandatory=$true)] [string]$ExeFullPath,
        [Parameter(Mandatory=$true)] [int]$MaxRunning
    )

    New-Item -ItemType Directory -Force -Path $BatchDir | Out-Null
    $orderedTargets = @($Targets | Sort-Object reader_rank, gordon_rank)
    $running = @()
    $completed = @()
    $nextIndex = 0

    while (($nextIndex -lt $orderedTargets.Count) -or ($running.Count -gt 0)) {
        while (($nextIndex -lt $orderedTargets.Count) -and ($running.Count -lt $MaxRunning)) {
            $running += Start-TargetSearch -Target $orderedTargets[$nextIndex] -BatchDir $BatchDir -ExeFullPath $ExeFullPath
            $nextIndex++
        }

        if ($running.Count -eq 0) {
            continue
        }

        $stillRunning = @()
        $completedThisPoll = @()
        foreach ($item in $running) {
            if ($item.process.HasExited) {
                $item.process.WaitForExit()
                $completedThisPoll += $item
            } else {
                $stillRunning += $item
            }
        }

        if ($completedThisPoll.Count -gt 0) {
            $completed += $completedThisPoll
            $running = @($stillRunning)
            continue
        }

        $running = @($stillRunning)
        Start-Sleep -Milliseconds 200
    }

    foreach ($item in $completed) {
        $item.process.WaitForExit()
        $item.process.Refresh()
    }

    $failed = @($completed | Where-Object { ($null -ne $_.process.ExitCode) -and ($_.process.ExitCode -ne 0) })
    if ($failed.Count -gt 0) {
        $messages = foreach ($item in $failed) {
            $tail = if (Test-Path -LiteralPath $item.stderr) { Get-Content -LiteralPath $item.stderr -Tail 5 } else { @() }
            "reader=$($item.target.reader_rank) gordon=$($item.target.gordon_rank) exit=$($item.process.ExitCode) stderr=$($tail -join ' | ')"
        }
        throw "one or more target searches failed: $($messages -join '; ')"
    }

    $summaries = foreach ($item in @($completed | Sort-Object { [int]$_.target.reader_rank }, { [int]$_.target.gordon_rank })) {
        Read-TargetSearchSummary -Item $item
    }
    return @($summaries)
}

$started = Get-Date
$watch = [Diagnostics.Stopwatch]::StartNew()

$exeFullPath = (Resolve-Path -LiteralPath $ExePath).Path
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$workFullPath = (Resolve-Path -LiteralPath $WorkDir).Path

$validation = $null
if (-not $SkipValidation) {
    & $exeFullPath --validation-battery --output $ValidationReportPath
    if ($LASTEXITCODE -ne 0) {
        throw "validation battery failed; see $ValidationReportPath"
    }
    $validation = Read-JsonFile -Path $ValidationReportPath
}

if (-not $SkipGenerate) {
    & $exeFullPath --generate-reader-candidates --output $GeneratedTargetsPath
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
    foreach ($plain in $gordonTargets) {
        $samePositionLetters = @(Get-SamePositionLetters -Plaintext $plain.plaintext -Ciphertext $reader.ciphertext)
        [pscustomobject]@{
            reader_rank = [int]$reader.reader_rank
            gordon_rank = [int]$plain.rank
            reader_start = $reader.start
            reader_rings = $reader.rings
            reader_active_pairs = $reader.active_pairs
            reader_ciphertext = $reader.ciphertext
            gordon_plaintext = $plain.plaintext
            impossible_same_position_count = [int]$samePositionLetters.Count
            impossible_same_position_letters = $samePositionLetters
        }
    }
}
$allTargets = @($allTargets | Sort-Object reader_rank, gordon_rank)
$skippedImpossibleTargets = @($allTargets | Where-Object { $_.impossible_same_position_count -gt 0 })
$targets = @($allTargets | Where-Object { $_.impossible_same_position_count -eq 0 })

if ($MaxConcurrentTargets -le 0) {
    $MaxConcurrentTargets = [Math]::Max(1, [Math]::Floor([Environment]::ProcessorCount / [Math]::Max(1, $ThreadsPerTarget)))
}

$targetSummaries = @()
$orderedSolutions = @()
$earlyStopTriggered = $false
$batchesRun = 0

if ($Mode -ne "ValidationOnly") {
    if ($Mode -eq "EarlyStop") {
        foreach ($readerGroup in @($targets | Group-Object reader_rank | Sort-Object { [int]$_.Name })) {
            $groupTargets = @($readerGroup.Group | Sort-Object gordon_rank)
            if ($groupTargets.Count -gt 0) {
                $batchDir = Join-Path $workFullPath ("pool_{0:D5}_reader_{1:D3}" -f $batchesRun, [int]$readerGroup.Name)
                $batchSummaries = Invoke-TargetPool -Targets $groupTargets -BatchDir $batchDir -ExeFullPath $exeFullPath -MaxRunning $MaxConcurrentTargets
                $targetSummaries += @($batchSummaries)
                $batchesRun++
            }
            $readerHits = @($targetSummaries | Where-Object { $_.reader_rank -eq [int]$readerGroup.Name -and $_.result_count -gt 0 } | Sort-Object gordon_rank)
            if ($readerHits.Count -gt 0) {
                $earlyStopTriggered = $true
                break
            }
        }
    } else {
        if ($targets.Count -gt 0) {
            $batchDir = Join-Path $workFullPath ("pool_{0:D5}" -f $batchesRun)
            $batchSummaries = Invoke-TargetPool -Targets $targets -BatchDir $batchDir -ExeFullPath $exeFullPath -MaxRunning $MaxConcurrentTargets
            $targetSummaries += @($batchSummaries)
            $batchesRun++
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
                output = $summary.output
            }
        }
    }
}

$watch.Stop()
$finished = Get-Date

$totalClassChecks = ($targetSummaries | Measure-Object -Property behavior_classes_checked -Sum).Sum
$totalLiteralRepresented = ($targetSummaries | Measure-Object -Property literal_states_represented -Sum).Sum
$summaryObject = [pscustomobject]@{
    mode = $Mode
    tier = $Tier
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
    target_pairing_count_searchable = $targets.Count
    target_pairing_count_searched = $targetSummaries.Count
    threads_per_target = $ThreadsPerTarget
    max_concurrent_targets = $MaxConcurrentTargets
    scheduling_mode = "dynamic_target_pool"
    total_worker_threads = $ThreadsPerTarget * $MaxConcurrentTargets
    start_index = $StartIndex
    max_behavior_classes = $(if ($MaxStates -gt 0) { $MaxStates } else { $null })
    early_stop_triggered = $earlyStopTriggered
    batches_run = $batchesRun
    aggregate_behavior_class_checks = $totalClassChecks
    aggregate_literal_state_equivalents = $totalLiteralRepresented
    aggregate_literal_equivalent_checks_per_second_wall = $(if ($watch.Elapsed.TotalSeconds -gt 0) { $totalLiteralRepresented / $watch.Elapsed.TotalSeconds } else { 0 })
    ordered_solutions = $orderedSolutions
    skipped_impossible_target_examples = @($skippedImpossibleTargets | Select-Object -First 20 reader_rank, gordon_rank, reader_ciphertext, gordon_plaintext, impossible_same_position_count, impossible_same_position_letters)
    targets = @($targetSummaries | Sort-Object reader_rank, gordon_rank | Select-Object -Property * -ExcludeProperty results)
}

$summaryObject | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
[pscustomobject]@{
    mode = $summaryObject.mode
    summary_path = $SummaryPath
    target_pairing_count_selected = $summaryObject.target_pairing_count_selected
    target_pairing_count_skipped_impossible = $summaryObject.target_pairing_count_skipped_impossible
    target_pairing_count_searchable = $summaryObject.target_pairing_count_searchable
    target_pairing_count_searched = $summaryObject.target_pairing_count_searched
    ordered_solution_count = @($orderedSolutions).Count
    wall_elapsed_seconds = $summaryObject.wall_elapsed_seconds
} | ConvertTo-Json -Depth 4
