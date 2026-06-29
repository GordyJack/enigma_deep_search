param(
    [string]$GpuFilterExe = ".\enigma_cuda_prefix_filter.exe",
    [string]$CpuSearchExe = ".\enigma_m3_search_fast.exe",
    [string]$Tier = "2",
    [string]$Plaintext = "REALITYISACONFLUX",
    [UInt64]$StartIndex = 0,
    [UInt64]$MaxStates = 10000000,
    [int]$PrefixLen = 13,
    [int]$ThreadsPerCandidate = 4,
    [int]$ProgressSeconds = 0,
    [string]$WorkDir = ".\gpu_hybrid_work",
    [string]$SummaryPath = ".\gpu_hybrid_summary.json"
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

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$survivorDir = Join-Path $WorkDir "survivors"
$fullDir = Join-Path $WorkDir "full"
New-Item -ItemType Directory -Force -Path $survivorDir | Out-Null
New-Item -ItemType Directory -Force -Path $fullDir | Out-Null

$gpuJson = Join-Path $WorkDir "gpu_prefix.json"
$totalWatch = [Diagnostics.Stopwatch]::StartNew()

& $GpuFilterExe --tier $Tier --plaintext $Plaintext --default-candidates --start-index $StartIndex --max-states $MaxStates --prefix-len $PrefixLen --survivor-dir $survivorDir --output $gpuJson
if ($LASTEXITCODE -ne 0) {
    throw "GPU prefix filter failed with code $LASTEXITCODE"
}

$cpuWatch = [Diagnostics.Stopwatch]::StartNew()
$procs = @()
foreach ($candidate in $candidates) {
    $stateList = Join-Path $survivorDir ("candidate_{0}_survivors.bin" -f $candidate.Id)
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
    $procs += Start-Process -FilePath $CpuSearchExe -ArgumentList $args -WorkingDirectory (Get-Location).Path -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
}
Wait-Process -Id ($procs | ForEach-Object Id)
$cpuWatch.Stop()
$totalWatch.Stop()

$failed = $procs | Where-Object { $_.ExitCode -ne 0 -and $null -ne $_.ExitCode }
if ($failed.Count -gt 0) {
    throw "one or more CPU full-solve processes failed"
}

$gpu = Get-Content -LiteralPath $gpuJson -Raw | ConvertFrom-Json
$orderedSolutions = @()
$candidateSummaries = foreach ($candidate in $candidates) {
    $jsonOut = Join-Path $fullDir ("candidate_{0}_full.json" -f $candidate.Id)
    $full = Get-Content -LiteralPath $jsonOut -Raw | ConvertFrom-Json
    $tierStats = @($full.tier_stats)[0]
    $gpuCandidate = @($gpu.candidates | Where-Object id -eq $candidate.Id)[0]
    foreach ($result in @($full.results)) {
        $orderedSolutions += [pscustomobject]@{
            id = $candidate.Id
            label = $candidate.Label
            ciphertext = $candidate.Ciphertext
            output = $jsonOut
            result = $result
        }
    }
    [pscustomobject]@{
        id = $candidate.Id
        label = $candidate.Label
        ciphertext = $candidate.Ciphertext
        gpu_prefix_survivors = [UInt64]$gpuCandidate.survivors
        gpu_prefix_elapsed_seconds = [double]$gpuCandidate.elapsed_seconds
        cpu_full_elapsed_seconds_reported = [double]$tierStats.elapsed_seconds
        result_count = [int]$full.result_count
        output = $jsonOut
    }
}

$summary = [pscustomobject]@{
    plaintext = $Plaintext
    tier = $Tier
    candidate_count = $candidates.Count
    start_index = $StartIndex
    max_states = $MaxStates
    prefix_len = $PrefixLen
    threads_per_candidate = $ThreadsPerCandidate
    total_worker_threads = $ThreadsPerCandidate * $candidates.Count
    gpu_prefix_wall_elapsed_seconds = [double]$gpu.wall_elapsed_seconds
    cpu_full_wall_elapsed_seconds = $cpuWatch.Elapsed.TotalSeconds
    total_wall_elapsed_seconds = $totalWatch.Elapsed.TotalSeconds
    literal_states_checked_per_candidate = $MaxStates
    aggregate_candidate_state_checks = $MaxStates * $candidates.Count
    literal_states_per_second_wall = $(if ($totalWatch.Elapsed.TotalSeconds -gt 0) { $MaxStates / $totalWatch.Elapsed.TotalSeconds } else { 0 })
    candidate_state_checks_per_second_wall = $(if ($totalWatch.Elapsed.TotalSeconds -gt 0) { ($MaxStates * $candidates.Count) / $totalWatch.Elapsed.TotalSeconds } else { 0 })
    gpu_prefix_output = $gpuJson
    ordered_solutions = $orderedSolutions
    candidates = $candidateSummaries
}

$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
$summary | ConvertTo-Json -Depth 8
