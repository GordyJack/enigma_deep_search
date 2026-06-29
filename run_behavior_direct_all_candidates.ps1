param(
    [string]$ExePath = ".\enigma_m3_search_fast.exe",
    [string]$Tier = "2",
    [string]$Plaintext = "REALITYISACONFLUX",
    [UInt64]$StartIndex = 0,
    [UInt64]$MaxStates = 0,
    [int]$ThreadsPerCandidate = 4,
    [int]$ProgressSeconds = 30,
    [int]$MaxResultsPerCandidate = 2147483647,
    [string]$OutputDir = ".\behavior_direct_outputs",
    [string]$SummaryPath = ".\behavior_direct_summary.json"
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

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$exeFullPath = (Resolve-Path -LiteralPath $ExePath).Path
$outputFullPath = (Resolve-Path -LiteralPath $OutputDir).Path

$jobs = @()
$started = Get-Date
$watch = [Diagnostics.Stopwatch]::StartNew()

foreach ($candidate in $candidates) {
    $jsonPath = Join-Path $outputFullPath ("candidate_{0}_direct.json" -f $candidate.Id)
    $args = @(
        "--tier", $Tier,
        "--plaintext", $Plaintext,
        "--ciphertext", $candidate.Ciphertext,
        "--threads", "$ThreadsPerCandidate",
        "--start-index", "$StartIndex",
        "--progress-seconds", "$ProgressSeconds",
        "--max-results", "$MaxResultsPerCandidate",
        "--skip-initial-tests",
        "--behavior-direct",
        "--output", $jsonPath
    )
    if ($MaxStates -gt 0) {
        $args += @("--max-states", "$MaxStates")
    }

    $jobs += Start-Job -Name ("candidate-{0}" -f $candidate.Id) -ScriptBlock {
        param($Exe, $ArgList, $CandidateId, $Label)
        & $Exe @ArgList 2>&1 | ForEach-Object {
            "[candidate $CandidateId $Label] $_"
        }
        if ($LASTEXITCODE -ne 0) {
            throw "candidate $CandidateId exited with code $LASTEXITCODE"
        }
    } -ArgumentList $exeFullPath, $args, $candidate.Id, $candidate.Label
}

try {
    while (($jobs | Where-Object State -eq "Running").Count -gt 0) {
        foreach ($job in $jobs) {
            Receive-Job -Job $job | Write-Host
        }
        Start-Sleep -Seconds 1
    }
    foreach ($job in $jobs) {
        Receive-Job -Job $job | Write-Host
    }
    $failed = $jobs | Where-Object State -ne "Completed"
    if ($failed.Count -gt 0) {
        $failed | Format-Table Id, Name, State | Out-String | Write-Error
        throw "one or more candidate searches failed"
    }
}
finally {
    $jobs | Remove-Job -Force
}

$watch.Stop()
$finished = Get-Date

$orderedSolutions = @()
$candidateSummaries = foreach ($candidate in $candidates) {
    $jsonPath = Join-Path $outputFullPath ("candidate_{0}_direct.json" -f $candidate.Id)
    $parsed = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
    $tierStats = @($parsed.tier_stats)[0]
    foreach ($result in @($parsed.results)) {
        $orderedSolutions += [pscustomobject]@{
            id = $candidate.Id
            label = $candidate.Label
            ciphertext = $candidate.Ciphertext
            output = $jsonPath
            result = $result
        }
    }
    [pscustomobject]@{
        id = $candidate.Id
        label = $candidate.Label
        ciphertext = $candidate.Ciphertext
        result_count = [int]$parsed.result_count
        behavior_classes_checked = [UInt64]$parsed.states_checked
        literal_states_represented = [UInt64]$parsed.states_checked * 104
        elapsed_seconds_reported = [double]$tierStats.elapsed_seconds
        stage10_pass = [UInt64]$tierStats.stage10_pass
        full_solves = [UInt64]$tierStats.full_solves
        output = $jsonPath
    }
}

$totalClassChecks = ($candidateSummaries | Measure-Object -Property behavior_classes_checked -Sum).Sum
$classesPerCandidate = if ($candidateSummaries.Count -gt 0) { @($candidateSummaries)[0].behavior_classes_checked } else { 0 }
$literalRepresentedPerCandidate = $classesPerCandidate * 104
$summary = [pscustomobject]@{
    plaintext = $Plaintext
    tier = $Tier
    candidate_count = $candidates.Count
    threads_per_candidate = $ThreadsPerCandidate
    total_worker_threads = $ThreadsPerCandidate * $candidates.Count
    start_index = $StartIndex
    max_behavior_classes = $(if ($MaxStates -gt 0) { $MaxStates } else { $null })
    started = $started.ToString("o")
    finished = $finished.ToString("o")
    wall_elapsed_seconds = $watch.Elapsed.TotalSeconds
    behavior_classes_checked_per_candidate = $classesPerCandidate
    aggregate_behavior_class_checks = $totalClassChecks
    literal_states_represented_per_candidate = $literalRepresentedPerCandidate
    aggregate_literal_state_equivalents = $totalClassChecks * 104
    behavior_classes_per_second_wall = $(if ($watch.Elapsed.TotalSeconds -gt 0) { $classesPerCandidate / $watch.Elapsed.TotalSeconds } else { 0 })
    aggregate_behavior_class_checks_per_second_wall = $(if ($watch.Elapsed.TotalSeconds -gt 0) { $totalClassChecks / $watch.Elapsed.TotalSeconds } else { 0 })
    literal_equivalent_states_per_second_wall = $(if ($watch.Elapsed.TotalSeconds -gt 0) { $literalRepresentedPerCandidate / $watch.Elapsed.TotalSeconds } else { 0 })
    aggregate_literal_equivalent_checks_per_second_wall = $(if ($watch.Elapsed.TotalSeconds -gt 0) { ($totalClassChecks * 104) / $watch.Elapsed.TotalSeconds } else { 0 })
    ordered_solutions = $orderedSolutions
    candidates = $candidateSummaries
}

$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
$summary | ConvertTo-Json -Depth 8
