param(
    [string]$GpuExePath = ".\enigma_cuda_prefix_filter.exe",
    [string]$CpuExePath = ".\enigma_m3_search_fast.exe",
    [string]$GeneratedTargetsPath = ".\story_clue_generated_14_selected_strict_latest.json",
    [string]$WorkDir = ".\mindorderchaos_staged_expansion",
    [string]$SummaryPath = ".\mindorderchaos_staged_expansion_summary.json",
    [string]$ReportPath = ".\mindorderchaos_staged_expansion_report.md",
    [string]$CsvPath = ".\mindorderchaos_staged_expansion_literal_settings.csv",
    [UInt64]$GpuSurvivorCap = 1000000,
    [UInt64]$CpuVerifySurvivorLimit = 50000,
    [int]$CpuThreads = 8,
    [int]$StopThreshold = 20,
    [int]$MaxResultsPerOption = 200,
    [int]$BalloonResultThreshold = 200,
    [switch]$NoGpuCoreCache
)

$ErrorActionPreference = "Stop"
$useGpuCoreCache = -not [bool]$NoGpuCoreCache

$TargetGordonPlaintext = "MINDORDERCHAOS"
$DisplayGordonText = "MIND+ORDER+CHAOS=REALITY"
$FullGordonPlaintext = "MINDORDERCHAOSREALITY"
$FunctionalReaders = @(
    "MOMENTHIDDEATH",
    "THEDAYHIDDEATH",
    "SECRETLOOPDEAD",
    "DEATHWASERASED",
    "DEATHREWRITTEN",
    "ONEYEARINWEEKS"
)
$ReaderPlugboardOrder = @("PE AF GR", "PE AF GR UT", "PE AF", "PE")
$FullBehaviorClasses = [UInt64]1425765120

function Read-JsonFile {
    param([Parameter(Mandatory=$true)] [string]$Path)
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Normalize-Letters {
    param([Parameter(Mandatory=$true)] [string]$Text)
    return ($Text.ToUpperInvariant() -replace '[^A-Z]', '')
}

function Test-SamePositionImpossible {
    param(
        [Parameter(Mandatory=$true)] [string]$Plaintext,
        [Parameter(Mandatory=$true)] [string]$Ciphertext
    )

    $plain = Normalize-Letters $Plaintext
    $cipher = Normalize-Letters $Ciphertext
    if ($plain.Length -ne $cipher.Length) {
        throw "plaintext/ciphertext length mismatch: $plain / $cipher"
    }
    for ($i = 0; $i -lt $plain.Length; $i++) {
        if ($plain[$i] -eq $cipher[$i]) {
            return $true
        }
    }
    return $false
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
        $tail = if (Test-Path -LiteralPath $StderrPath) { Get-Content -LiteralPath $StderrPath -Tail 20 } else { @() }
        throw "$Label failed with exit code $($proc.ExitCode): $($tail -join ' | ')"
    }
    return $watch.Elapsed.TotalSeconds
}

$script:RotorWirings = @{
    "I" = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
    "II" = "AJDKSIRUXBLHWTMCQGZNPYFVOE"
    "III" = "BDFHJLCPRTXVZNYEIWGAKMUSQO"
    "IV" = "ESOVPZJAYQUIRHXLNFTGKDCMWB"
    "V" = "VZBRGITYUPSDNHLXAWMJQOFECK"
}
$script:RotorNotches = @{
    "I" = "Q"
    "II" = "E"
    "III" = "V"
    "IV" = "J"
    "V" = "Z"
}
$script:Reflectors = @{
    "B" = "YRUHQSLDPXNGOKMIEBFZCWVJAT"
    "C" = "FVPJIAOYEDRZXWGCTKUQSBNMHL"
}

function Convert-LetterToInt {
    param([Parameter(Mandatory=$true)] [char]$Letter)
    return ([int][char]$Letter - [int][char]'A')
}

function Convert-IntToLetter {
    param([Parameter(Mandatory=$true)] [int]$Value)
    return [char]([int][char]'A' + $Value)
}

function Invoke-RotorForward {
    param(
        [int]$Index,
        [string]$Rotor,
        [int]$Position,
        [int]$Ring
    )
    $shifted = ($Index + $Position - $Ring + 26) % 26
    $wired = Convert-LetterToInt $script:RotorWirings[$Rotor][$shifted]
    return ($wired - $Position + $Ring + 26) % 26
}

function Invoke-RotorBackward {
    param(
        [int]$Index,
        [string]$Rotor,
        [int]$Position,
        [int]$Ring
    )
    $shifted = ($Index + $Position - $Ring + 26) % 26
    $wiring = $script:RotorWirings[$Rotor]
    for ($i = 0; $i -lt 26; $i++) {
        if ((Convert-LetterToInt $wiring[$i]) -eq $shifted) {
            return ($i - $Position + $Ring + 26) % 26
        }
    }
    throw "rotor inverse lookup failed for $Rotor"
}

function New-PlugboardMap {
    param([object[]]$PlugboardPairs)

    $map = New-Object int[] 26
    for ($i = 0; $i -lt 26; $i++) {
        $map[$i] = $i
    }
    foreach ($pairObject in @($PlugboardPairs)) {
        if ($null -eq $pairObject) {
            continue
        }
        $pair = [string]$pairObject
        if ($pair.Length -ne 2) {
            throw "invalid plugboard pair: $pair"
        }
        $a = Convert-LetterToInt $pair[0]
        $b = Convert-LetterToInt $pair[1]
        $map[$a] = $b
        $map[$b] = $a
    }
    return $map
}

function Invoke-EnigmaEncrypt {
    param(
        [Parameter(Mandatory=$true)] [string]$Plaintext,
        [Parameter(Mandatory=$true)] [string]$Reflector,
        [Parameter(Mandatory=$true)] [object[]]$RotorsLeftToRight,
        [Parameter(Mandatory=$true)] [string]$StartLeftToRight,
        [Parameter(Mandatory=$true)] [string]$RingsLeftToRight,
        [object[]]$PlugboardPairs = @()
    )

    $text = Normalize-Letters $Plaintext
    $rotors = @($RotorsLeftToRight | ForEach-Object { [string]$_ })
    if ($rotors.Count -ne 3) {
        throw "expected 3 rotors, got $($rotors.Count)"
    }
    $positions = @(
        (Convert-LetterToInt $StartLeftToRight[0]),
        (Convert-LetterToInt $StartLeftToRight[1]),
        (Convert-LetterToInt $StartLeftToRight[2])
    )
    $rings = @(
        (Convert-LetterToInt $RingsLeftToRight[0]),
        (Convert-LetterToInt $RingsLeftToRight[1]),
        (Convert-LetterToInt $RingsLeftToRight[2])
    )
    $plug = New-PlugboardMap -PlugboardPairs @($PlugboardPairs)
    $output = New-Object System.Text.StringBuilder

    foreach ($ch in $text.ToCharArray()) {
        $middleAtNotch = $positions[1] -eq (Convert-LetterToInt $script:RotorNotches[$rotors[1]][0])
        $rightAtNotch = $positions[2] -eq (Convert-LetterToInt $script:RotorNotches[$rotors[2]][0])
        if ($middleAtNotch) {
            $positions[0] = ($positions[0] + 1) % 26
        }
        if ($middleAtNotch -or $rightAtNotch) {
            $positions[1] = ($positions[1] + 1) % 26
        }
        $positions[2] = ($positions[2] + 1) % 26

        $index = Convert-LetterToInt $ch
        $index = $plug[$index]
        for ($slot = 2; $slot -ge 0; $slot--) {
            $index = Invoke-RotorForward -Index $index -Rotor $rotors[$slot] -Position $positions[$slot] -Ring $rings[$slot]
        }
        $index = Convert-LetterToInt $script:Reflectors[$Reflector][$index]
        for ($slot = 0; $slot -lt 3; $slot++) {
            $index = Invoke-RotorBackward -Index $index -Rotor $rotors[$slot] -Position $positions[$slot] -Ring $rings[$slot]
        }
        $index = $plug[$index]
        [void]$output.Append((Convert-IntToLetter $index))
    }
    return $output.ToString()
}

function Get-AestheticNotes {
    param([Parameter(Mandatory=$true)] [object]$Result)

    $notes = New-Object System.Collections.Generic.List[string]
    $pairCount = [int]$Result.plugboard_pair_count
    $notes.Add("$pairCount Gordon plugboard pairs")
    if ($pairCount -le 8) {
        $notes.Add("lower-than-max plugboard count")
    }
    if ([string]$Result.reflector -eq "B") {
        $notes.Add("reflector B")
    }
    if ([string]$Result.rings_left_to_right -match '^(.)\1\1$') {
        $notes.Add("triple ring letters")
    }
    return ($notes -join "; ")
}

$started = Get-Date
$watch = [Diagnostics.Stopwatch]::StartNew()
$repoDir = (Get-Location).Path
$gpuExe = (Resolve-Path -LiteralPath $GpuExePath).Path
$cpuExe = (Resolve-Path -LiteralPath $CpuExePath).Path
$generatedPath = (Resolve-Path -LiteralPath $GeneratedTargetsPath).Path

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$workFullPath = (Resolve-Path -LiteralPath $WorkDir).Path

$generated = Read-JsonFile -Path $generatedPath
if ($generated.reader_mode -ne "strict") {
    throw "expected strict reader generated target file, got reader_mode=$($generated.reader_mode)"
}

foreach ($candidate in @($generated.reader_candidates)) {
    if ($FunctionalReaders -contains [string]$candidate.reader_plaintext) {
        if ($candidate.start -ne "GJM" -or $candidate.rings -ne "MMM") {
            throw "reader setting drift for $($candidate.reader_plaintext): $($candidate.start)/$($candidate.rings)"
        }
        if ($ReaderPlugboardOrder -notcontains [string]$candidate.active_pairs) {
            throw "unexpected reader plugboard option: $($candidate.active_pairs)"
        }
    }
}

$targetMap = @{}
$targetId = 1
foreach ($reader in @($generated.reader_candidates)) {
    foreach ($gordon in @($generated.gordon_targets)) {
        if ([int]$reader.normalized_length -ne [int]$gordon.normalized_length) {
            continue
        }
        if (($FunctionalReaders -contains [string]$reader.reader_plaintext) -and
            [string]$gordon.plaintext -eq $TargetGordonPlaintext) {
            $optionRank = [array]::IndexOf($ReaderPlugboardOrder, [string]$reader.active_pairs) + 1
            $target = [pscustomobject]@{
                target_id = $targetId
                reader_plaintext = [string]$reader.reader_plaintext
                reader_rank = [int]$reader.reader_plaintext_rank
                reader_generated_rank = [int]$reader.reader_generated_rank
                reader_start = [string]$reader.start
                reader_rings = [string]$reader.rings
                option_rank = $optionRank
                reader_active_pairs = [string]$reader.active_pairs
                reader_ciphertext = [string]$reader.ciphertext
                gordon_rank = [int]$gordon.rank
                gordon_match_plaintext = [string]$gordon.plaintext
                same_position_impossible = [bool](Test-SamePositionImpossible -Plaintext $gordon.plaintext -Ciphertext $reader.ciphertext)
            }
            $targetMap["$($target.reader_plaintext)|$($target.option_rank)"] = $target
        }
        $targetId++
    }
}

$readerStates = @{}
foreach ($readerPlaintext in $FunctionalReaders) {
    $readerStates[$readerPlaintext] = [pscustomobject]@{
        reader_plaintext = $readerPlaintext
        gordon_match_plaintext = $TargetGordonPlaintext
        display_gordon_text = $DisplayGordonText
        full_gordon_plaintext = $FullGordonPlaintext
        cumulative_literal_gordon_settings = 0
        stopped_after_threshold = $false
        stopped_after_option_rank = $null
        incomplete = $false
        ballooned = $false
        option_results = New-Object System.Collections.Generic.List[object]
    }
}

$allLiteralRows = New-Object System.Collections.Generic.List[object]
$totalGpuWall = 0.0
$totalCpuWall = 0.0
$totalChecks = [UInt64]0

foreach ($optionRank in 1..$ReaderPlugboardOrder.Count) {
    $activePairs = $ReaderPlugboardOrder[$optionRank - 1]
    $batchTargets = New-Object System.Collections.Generic.List[object]

    foreach ($readerPlaintext in $FunctionalReaders) {
        $state = $readerStates[$readerPlaintext]
        if ($state.stopped_after_threshold -or $state.incomplete) {
            continue
        }
        $targetKey = "$readerPlaintext|$optionRank"
        if (-not $targetMap.ContainsKey($targetKey)) {
            $state.option_results.Add([pscustomobject]@{
                option_rank = $optionRank
                reader_active_pairs = $activePairs
                reader_ciphertext = $null
                target_id = $null
                skipped = $true
                skip_reason = "target_missing"
                gpu_survivors = 0
                cpu_verified_literal_gordon_settings = 0
                cumulative_after_option = [int]$state.cumulative_literal_gordon_settings
                ballooned = $false
                incomplete = $false
                literal_settings = @()
            })
            continue
        }
        $target = $targetMap[$targetKey]
        if ($target.same_position_impossible) {
            $state.option_results.Add([pscustomobject]@{
                option_rank = $optionRank
                reader_active_pairs = $activePairs
                reader_ciphertext = $target.reader_ciphertext
                target_id = [int]$target.target_id
                skipped = $true
                skip_reason = "same_position_impossible"
                gpu_survivors = 0
                cpu_verified_literal_gordon_settings = 0
                cumulative_after_option = [int]$state.cumulative_literal_gordon_settings
                ballooned = $false
                incomplete = $false
                literal_settings = @()
            })
            continue
        }
        $batchTargets.Add($target)
    }

    if ($batchTargets.Count -eq 0) {
        continue
    }

    $optionDir = Join-Path $workFullPath ("option_{0:D2}_{1}" -f $optionRank, ($activePairs -replace '[^A-Z0-9]+', '_'))
    New-Item -ItemType Directory -Force -Path $optionDir | Out-Null
    $candidateFile = Join-Path $optionDir "targets.tsv"
    $candidateLines = foreach ($target in $batchTargets.ToArray()) {
        "{0}`treader_{1:D3}_option_{2:D2}`t{3}" -f [int]$target.target_id, [int]$target.reader_rank, [int]$target.option_rank, $target.reader_ciphertext
    }
    $candidateLines | Set-Content -LiteralPath $candidateFile -Encoding ASCII

    $gpuOutput = Join-Path $optionDir "gpu_prefix_results.json"
    $gpuStdout = Join-Path $optionDir "gpu_prefix.out.txt"
    $gpuStderr = Join-Path $optionDir "gpu_prefix.err.txt"
    $gpuArgs = @(
        "--tier", "2",
        "--plaintext", $TargetGordonPlaintext,
        "--candidate-file", $candidateFile,
        "--behavior-direct",
        "--start-index", "0",
        "--max-states", "$FullBehaviorClasses",
        "--prefix-len", "14",
        "--survivor-dir", $optionDir,
        "--survivor-cap", "$GpuSurvivorCap",
        "--output", $gpuOutput
    )
    if ($useGpuCoreCache) {
        $gpuArgs += "--gpu-core-cache"
    } else {
        $gpuArgs += "--no-gpu-core-cache"
    }

    Write-Host ("Starting option {0}: {1}; {2} reader target(s)." -f $optionRank, $activePairs, $batchTargets.Count)
    $gpuWall = Invoke-ProcessChecked -FilePath $gpuExe -ArgumentList $gpuArgs -WorkingDirectory $repoDir -StdoutPath $gpuStdout -StderrPath $gpuStderr -Label "GPU option $optionRank"
    $totalGpuWall += $gpuWall
    $totalChecks += [UInt64]$FullBehaviorClasses * [UInt64]$batchTargets.Count
    $gpu = Read-JsonFile -Path $gpuOutput
    $gpuById = @{}
    foreach ($candidate in @($gpu.candidates)) {
        $gpuById["$($candidate.id)"] = $candidate
    }

    foreach ($target in $batchTargets.ToArray()) {
        $state = $readerStates[$target.reader_plaintext]
        $gpuCandidate = $gpuById["$($target.target_id)"]
        if ($null -eq $gpuCandidate) {
            throw "GPU output missing target id $($target.target_id)"
        }

        $optionResult = [pscustomobject]@{
            option_rank = $optionRank
            reader_active_pairs = $target.reader_active_pairs
            reader_ciphertext = $target.reader_ciphertext
            target_id = [int]$target.target_id
            skipped = $false
            skip_reason = $null
            gpu_survivors = [UInt64]$gpuCandidate.survivors
            gpu_survivors_stored = [UInt64]$gpuCandidate.survivors_stored
            gpu_elapsed_seconds = [double]$gpuCandidate.elapsed_seconds
            gpu_states_per_second = [double]$gpuCandidate.states_per_second
            cpu_verify_wall_seconds = 0.0
            cpu_verified_literal_gordon_settings = 0
            cumulative_after_option = [int]$state.cumulative_literal_gordon_settings
            ballooned = $false
            incomplete = $false
            incomplete_reason = $null
            cpu_output = $null
            survivor_path = $null
            literal_settings = New-Object System.Collections.Generic.List[object]
        }

        if ([bool]$gpuCandidate.survivor_overflow) {
            $optionResult.incomplete = $true
            $optionResult.incomplete_reason = "gpu_survivor_cap_overflow"
            $state.incomplete = $true
            $state.ballooned = $true
            $state.option_results.Add($optionResult)
            continue
        }
        if ([UInt64]$gpuCandidate.survivors -gt $CpuVerifySurvivorLimit) {
            $optionResult.incomplete = $true
            $optionResult.incomplete_reason = "cpu_verify_survivor_limit_exceeded"
            $state.incomplete = $true
            $state.ballooned = $true
            $state.option_results.Add($optionResult)
            continue
        }
        if ([UInt64]$gpuCandidate.survivors -eq 0) {
            $state.option_results.Add($optionResult)
            continue
        }

        $survivorPath = Join-Path $optionDir ("candidate_{0}_survivors.bin" -f $target.target_id)
        if (-not (Test-Path -LiteralPath $survivorPath)) {
            throw "expected survivor file does not exist: $survivorPath"
        }
        $verifyDir = Join-Path $optionDir ("verify_candidate_{0}" -f $target.target_id)
        New-Item -ItemType Directory -Force -Path $verifyDir | Out-Null
        $cpuOutput = Join-Path $verifyDir "cpu_verify.json"
        $cpuStdout = Join-Path $verifyDir "cpu_verify.out.txt"
        $cpuStderr = Join-Path $verifyDir "cpu_verify.err.txt"
        $cpuArgs = @(
            "--tier", "2",
            "--plaintext", $TargetGordonPlaintext,
            "--ciphertext", $target.reader_ciphertext,
            "--behavior-class-list-binary", $survivorPath,
            "--threads", "$CpuThreads",
            "--progress-seconds", "0",
            "--max-results", "$MaxResultsPerOption",
            "--skip-initial-tests",
            "--output", $cpuOutput
        )
        $cpuWall = Invoke-ProcessChecked -FilePath $cpuExe -ArgumentList $cpuArgs -WorkingDirectory $repoDir -StdoutPath $cpuStdout -StderrPath $cpuStderr -Label "CPU verify target $($target.target_id)"
        $totalCpuWall += $cpuWall
        $cpu = Read-JsonFile -Path $cpuOutput

        $optionResult.cpu_verify_wall_seconds = $cpuWall
        $optionResult.cpu_verified_literal_gordon_settings = [int]$cpu.result_count
        $optionResult.cumulative_after_option = [int]$state.cumulative_literal_gordon_settings + [int]$cpu.result_count
        $optionResult.cpu_output = $cpuOutput
        $optionResult.survivor_path = $survivorPath
        if ($MaxResultsPerOption -gt 0 -and [int]$cpu.result_count -ge $MaxResultsPerOption) {
            $optionResult.incomplete = $true
            $optionResult.incomplete_reason = "max_results_per_option_reached"
            $state.incomplete = $true
        }
        if ([int]$cpu.result_count -gt $BalloonResultThreshold) {
            $optionResult.ballooned = $true
            $state.ballooned = $true
        }

        $literalIndex = 0
        foreach ($result in @($cpu.results)) {
            $literalIndex++
            $fullCipher = Invoke-EnigmaEncrypt `
                -Plaintext $FullGordonPlaintext `
                -Reflector ([string]$result.reflector) `
                -RotorsLeftToRight @($result.rotors_left_to_right) `
                -StartLeftToRight ([string]$result.start_left_to_right) `
                -RingsLeftToRight ([string]$result.rings_left_to_right) `
                -PlugboardPairs @($result.plugboard_pairs)
            $first14 = $fullCipher.Substring(0, 14)
            $suffix7 = $fullCipher.Substring(14)
            $verificationOk = ($first14 -eq [string]$result.verification_ciphertext) -and ($first14 -eq [string]$target.reader_ciphertext)
            if (-not $verificationOk) {
                throw "continuous full-message verification failed for target $($target.target_id) result $literalIndex"
            }
            $setting = [pscustomobject]@{
                reader_plaintext = $target.reader_plaintext
                gordon_match_plaintext = $TargetGordonPlaintext
                display_gordon_text = $DisplayGordonText
                full_gordon_plaintext = $FullGordonPlaintext
                reader_active_pairs = $target.reader_active_pairs
                reader_ciphertext = $target.reader_ciphertext
                option_rank = [int]$target.option_rank
                target_id = [int]$target.target_id
                option_result_index = $literalIndex
                literal_state_index = [UInt64]$result.literal_state_index
                reflector = [string]$result.reflector
                rotor_order = (@($result.rotors_left_to_right) -join " ")
                start_window = [string]$result.start_left_to_right
                rings = [string]$result.rings_left_to_right
                gordon_plugboard_pairs = (@($result.plugboard_pairs) -join " ")
                gordon_plugboard_pair_count = [int]$result.plugboard_pair_count
                first14_gordon_ciphertext = $first14
                full_gordon_ciphertext = $fullCipher
                reality_suffix_ciphertext = $suffix7
                continuous_full_message_verified = $true
                aesthetic_notes = (Get-AestheticNotes -Result $result)
            }
            $optionResult.literal_settings.Add($setting)
            $allLiteralRows.Add($setting)
        }

        $state.cumulative_literal_gordon_settings = [int]$state.cumulative_literal_gordon_settings + [int]$cpu.result_count
        $state.option_results.Add($optionResult)
        Write-Host ("{0} / {1}: option {2} found {3}; cumulative {4}." -f $target.reader_plaintext, $TargetGordonPlaintext, $optionRank, [int]$cpu.result_count, [int]$state.cumulative_literal_gordon_settings)
    }

    foreach ($readerPlaintext in $FunctionalReaders) {
        $state = $readerStates[$readerPlaintext]
        if ((-not $state.stopped_after_threshold) -and (-not $state.incomplete) -and [int]$state.cumulative_literal_gordon_settings -ge $StopThreshold) {
            $state.stopped_after_threshold = $true
            $state.stopped_after_option_rank = $optionRank
        }
    }
}

$watch.Stop()
$finished = Get-Date

if ($allLiteralRows.Count -gt 0) {
    $allLiteralRows |
        Sort-Object reader_plaintext, option_rank, option_result_index |
        Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
} else {
    @() | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
}

$readerSummaries = @($FunctionalReaders | ForEach-Object { $readerStates[$_] })
$summaryObject = [pscustomobject]@{
    mode = "mindorderchaos_staged_literal_expansion"
    started = $started.ToString("o")
    finished = $finished.ToString("o")
    wall_elapsed_seconds = $watch.Elapsed.TotalSeconds
    target_gordon_match_plaintext = $TargetGordonPlaintext
    display_gordon_text = $DisplayGordonText
    full_gordon_plaintext = $FullGordonPlaintext
    reader_settings_locked = [pscustomobject]@{
        reflector = "B"
        rotors_left_to_right = "III I IV"
        start_window = "GJM"
        rings = "MMM"
        plugboard_option_order = $ReaderPlugboardOrder
    }
    gordon_search_assumptions = [pscustomobject]@{
        tier = 2
        reflectors = "B C"
        rotor_pool = "I II III IV V"
        rotor_order_count = 60
        max_gordon_plugboard_pairs = 10
        behavior_classes_per_target = $FullBehaviorClasses
        behavior_direct = $true
        gpu_core_cache = [bool]$useGpuCoreCache
    }
    stop_threshold_per_reader_phrase = $StopThreshold
    max_results_per_option = $MaxResultsPerOption
    gpu_survivor_cap = $GpuSurvivorCap
    cpu_verify_survivor_limit = $CpuVerifySurvivorLimit
    balloon_result_threshold = $BalloonResultThreshold
    total_literal_gordon_settings_reported = $allLiteralRows.Count
    total_gpu_behavior_checks = $totalChecks
    total_gpu_wall_seconds = $totalGpuWall
    total_cpu_verify_wall_seconds = $totalCpuWall
    aggregate_gpu_behavior_checks_per_second = $(if ($totalGpuWall -gt 0) { $totalChecks / $totalGpuWall } else { 0 })
    reader_phrase_summaries = $readerSummaries
    literal_gordon_settings = @($allLiteralRows.ToArray())
}
$summaryObject | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8

$reportLines = New-Object System.Collections.Generic.List[string]
$reportLines.Add("# MINDORDERCHAOS Staged Literal Expansion")
$reportLines.Add("")
$reportLines.Add("- Gordon match plaintext: ``$TargetGordonPlaintext``")
$reportLines.Add("- Display-facing Gordon text: ``$DisplayGordonText``")
$reportLines.Add("- Full continuous Gordon plaintext: ``$FullGordonPlaintext``")
$reportLines.Add("- Reader settings: reflector B, rotors III I IV, start GJM, rings MMM")
$reportLines.Add("- Reader plugboard option order: $($ReaderPlugboardOrder -join ' -> ')")
$reportLines.Add("- Stop threshold: $StopThreshold cumulative CPU-verified literal Gordon settings per reader phrase")
$reportLines.Add("- Total literal Gordon settings reported: $($allLiteralRows.Count)")
$reportLines.Add("- Wall time: $([Math]::Round($watch.Elapsed.TotalSeconds, 3)) seconds")
$reportLines.Add("")
$reportLines.Add("## Reader Summary")
$reportLines.Add("")
$reportLines.Add("| Reader plaintext | Cumulative settings | Tested options | Stopped at threshold | Incomplete | Ballooned |")
$reportLines.Add("| --- | ---: | ---: | --- | --- | --- |")
foreach ($readerPlaintext in $FunctionalReaders) {
    $state = $readerStates[$readerPlaintext]
    $tested = @($state.option_results | Where-Object { -not $_.skipped }).Count
    $reportLines.Add("| ``$($state.reader_plaintext)`` | $($state.cumulative_literal_gordon_settings) | $tested | $($state.stopped_after_threshold) | $($state.incomplete) | $($state.ballooned) |")
}
$reportLines.Add("")
$reportLines.Add("## Option Counts")
$reportLines.Add("")
$reportLines.Add("| Reader plaintext | Option | Reader ciphertext | GPU survivors | CPU-verified settings | Cumulative after option | Status |")
$reportLines.Add("| --- | --- | --- | ---: | ---: | ---: | --- |")
foreach ($readerPlaintext in $FunctionalReaders) {
    $state = $readerStates[$readerPlaintext]
    foreach ($option in $state.option_results.ToArray()) {
        $status = if ($option.skipped) { "skipped: $($option.skip_reason)" } elseif ($option.incomplete) { "incomplete: $($option.incomplete_reason)" } elseif ($option.ballooned) { "ballooned" } else { "complete" }
        $cipher = if ($null -eq $option.reader_ciphertext) { "" } else { "``$($option.reader_ciphertext)``" }
        $reportLines.Add("| ``$readerPlaintext`` | $($option.option_rank) ``$($option.reader_active_pairs)`` | $cipher | $($option.gpu_survivors) | $($option.cpu_verified_literal_gordon_settings) | $($option.cumulative_after_option) | $status |")
    }
}
$reportLines.Add("")
$reportLines.Add("## Literal Settings")
$reportLines.Add("")
$reportLines.Add("Full literal settings are included in ``$CsvPath`` and in the ``literal_gordon_settings`` array of ``$SummaryPath``.")
$reportLines.Add("Each row includes reflector, rotor order, start/window, rings, Gordon plugboard pairs, the first-14 ciphertext, the full continuous ciphertext, and the 7-letter ``REALITY`` suffix ciphertext.")
$reportLines | Set-Content -LiteralPath $ReportPath -Encoding UTF8

[pscustomobject]@{
    mode = $summaryObject.mode
    summary_path = $SummaryPath
    report_path = $ReportPath
    csv_path = $CsvPath
    wall_elapsed_seconds = $summaryObject.wall_elapsed_seconds
    total_literal_gordon_settings_reported = $summaryObject.total_literal_gordon_settings_reported
    aggregate_gpu_behavior_checks_per_second = $summaryObject.aggregate_gpu_behavior_checks_per_second
    reader_counts = @($readerSummaries | Select-Object reader_plaintext, cumulative_literal_gordon_settings, stopped_after_threshold, incomplete, ballooned)
} | ConvertTo-Json -Depth 8
