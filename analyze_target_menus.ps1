param(
    [string]$GeneratedTargetsPath = ".\generated_reader_candidates_96.json",
    [string]$OutputPath = ".\target_menu_diagnostics.json"
)

$ErrorActionPreference = "Stop"

function Normalize-Letters {
    param([Parameter(Mandatory=$true)] [string]$Text)
    return ($Text.ToUpperInvariant() -replace '[^A-Z]', '')
}

function Get-SamePositions {
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

function Get-MenuMetrics {
    param(
        [Parameter(Mandatory=$true)] [string]$Plaintext,
        [Parameter(Mandatory=$true)] [string]$Ciphertext,
        [Parameter(Mandatory=$true)] [int]$PrefixLength
    )

    $plain = Normalize-Letters $Plaintext
    $cipher = Normalize-Letters $Ciphertext
    if ($plain.Length -ne $cipher.Length) {
        throw "plaintext/ciphertext length mismatch: $plain / $cipher"
    }
    if ($PrefixLength -lt 1 -or $PrefixLength -gt $plain.Length) {
        throw "bad prefix length $PrefixLength"
    }

    $present = New-Object bool[] 26
    $degree = New-Object int[] 26
    $adj = @()
    for ($i = 0; $i -lt 26; $i++) {
        $adj += ,@()
    }

    for ($i = 0; $i -lt $PrefixLength; $i++) {
        $a = [int][char]$plain[$i] - [int][char]'A'
        $b = [int][char]$cipher[$i] - [int][char]'A'
        $present[$a] = $true
        $present[$b] = $true
        $degree[$a]++
        $degree[$b]++
        if ($a -ne $b) {
            $adj[$a] += $b
            $adj[$b] += $a
        }
    }

    $nodeCount = 0
    $maxDegree = 0
    $visited = New-Object bool[] 26
    $componentSizes = @()

    for ($i = 0; $i -lt 26; $i++) {
        if ($present[$i]) {
            $nodeCount++
            if ($degree[$i] -gt $maxDegree) {
                $maxDegree = $degree[$i]
            }
        }
    }

    for ($i = 0; $i -lt 26; $i++) {
        if (-not $present[$i] -or $visited[$i]) {
            continue
        }

        $queue = New-Object System.Collections.Generic.Queue[int]
        $queue.Enqueue($i)
        $visited[$i] = $true
        $size = 0
        while ($queue.Count -gt 0) {
            $cur = $queue.Dequeue()
            $size++
            foreach ($next in $adj[$cur]) {
                if (-not $visited[$next]) {
                    $visited[$next] = $true
                    $queue.Enqueue($next)
                }
            }
        }
        $componentSizes += $size
    }

    $componentSizes = @($componentSizes | Sort-Object -Descending)
    $componentCount = $componentSizes.Count
    $cycleRank = [Math]::Max(0, $PrefixLength - $nodeCount + $componentCount)
    $uniquePlain = @(($plain.Substring(0, $PrefixLength).ToCharArray() | Sort-Object -Unique)).Count
    $uniqueCipher = @(($cipher.Substring(0, $PrefixLength).ToCharArray() | Sort-Object -Unique)).Count
    $repeatedPlain = $PrefixLength - $uniquePlain
    $repeatedCipher = $PrefixLength - $uniqueCipher
    $largestComponent = if ($componentSizes.Count -gt 0) { [int]$componentSizes[0] } else { 0 }

    $strengthScore = ($cycleRank * 100) + ($largestComponent * 10) + (($repeatedPlain + $repeatedCipher) * 3) + ($maxDegree * 2)

    return [pscustomobject]@{
        prefix_length = $PrefixLength
        edges = $PrefixLength
        active_nodes = $nodeCount
        component_count = $componentCount
        largest_component = $largestComponent
        component_sizes = $componentSizes
        cycle_rank = $cycleRank
        max_degree = $maxDegree
        repeated_plain_letters = $repeatedPlain
        repeated_cipher_letters = $repeatedCipher
        strength_score = $strengthScore
    }
}

$generated = Get-Content -LiteralPath $GeneratedTargetsPath -Raw | ConvertFrom-Json
$readerCandidates = @($generated.reader_candidates)
$gordonTargets = @($generated.gordon_plaintexts)

if ($readerCandidates.Count -ne 96) {
    throw "expected 96 reader candidates, got $($readerCandidates.Count)"
}
if ($gordonTargets.Count -ne 8) {
    throw "expected 8 Gordon plaintexts, got $($gordonTargets.Count)"
}

$viable = @()
$impossible = @()

foreach ($reader in $readerCandidates) {
    foreach ($gordon in $gordonTargets) {
        $same = @(Get-SamePositions -Plaintext $gordon.plaintext -Ciphertext $reader.ciphertext)
        $target = [ordered]@{
            reader_rank = [int]$reader.reader_rank
            gordon_rank = [int]$gordon.rank
            reader_start = $reader.start
            reader_rings = $reader.rings
            reader_active_pairs = $reader.active_pairs
            reader_ciphertext = $reader.ciphertext
            gordon_plaintext = $gordon.plaintext
            impossible_same_position_count = $same.Count
        }

        if ($same.Count -gt 0) {
            $target.impossible_same_position_letters = $same
            $impossible += [pscustomobject]$target
            continue
        }

        $prefixMetrics = @()
        foreach ($prefix in 5,6,7,8,9,10,17) {
            $prefixMetrics += Get-MenuMetrics -Plaintext $gordon.plaintext -Ciphertext $reader.ciphertext -PrefixLength $prefix
        }
        $full = $prefixMetrics | Where-Object { $_.prefix_length -eq 17 } | Select-Object -First 1
        $target.full_menu_strength_score = $full.strength_score
        $target.full_cycle_rank = $full.cycle_rank
        $target.full_largest_component = $full.largest_component
        $target.full_max_degree = $full.max_degree
        $target.prefix_metrics = $prefixMetrics
        $viable += [pscustomobject]$target
    }
}

$strongest = @($viable | Sort-Object -Property full_menu_strength_score, full_cycle_rank, full_largest_component -Descending | Select-Object -First 20)
$weakest = @($viable | Sort-Object -Property full_menu_strength_score, full_cycle_rank, full_largest_component | Select-Object -First 20)

$report = [pscustomobject]@{
    generated_targets = $GeneratedTargetsPath
    reader_candidate_count = $readerCandidates.Count
    gordon_plaintext_count = $gordonTargets.Count
    total_pairings = $readerCandidates.Count * $gordonTargets.Count
    viable_pairings = $viable.Count
    impossible_pairings = $impossible.Count
    final_result_order_note = "Diagnostics only. Final result order remains reader rank, Gordon rank, machine tie-breakers."
    score_note = "Higher score means a denser repeated-letter/menu graph, not higher final preference."
    strongest_examples = $strongest
    weakest_examples = $weakest
    viable_targets = @($viable | Sort-Object reader_rank, gordon_rank)
    impossible_target_examples = @($impossible | Select-Object -First 20)
}

$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $OutputPath -Encoding UTF8

[pscustomobject]@{
    output = $OutputPath
    total_pairings = $report.total_pairings
    viable_pairings = $report.viable_pairings
    impossible_pairings = $report.impossible_pairings
    strongest_example = if ($strongest.Count -gt 0) { "reader $($strongest[0].reader_rank), Gordon $($strongest[0].gordon_rank), score $($strongest[0].full_menu_strength_score)" } else { $null }
    weakest_example = if ($weakest.Count -gt 0) { "reader $($weakest[0].reader_rank), Gordon $($weakest[0].gordon_rank), score $($weakest[0].full_menu_strength_score)" } else { $null }
} | ConvertTo-Json -Depth 4
