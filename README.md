# Enigma exhaustive search

Dependency-free C++17 searchers for Enigma I / M3 crib searches with an unknown
plugboard solved as constraints instead of brute-forced.

The recommended exact path is:

- `run_phrase_pair_first.ps1`: fastest current runner when the goal is to find
  which reader/Gordon phrase pairs are possible. It batches all generated reader
  variants for one phrase pair on the GPU, verifies any survivors on CPU, then
  stops that phrase pair as soon as one exact Enigma solution is proven.
- `src/enigma_m3_search_fast.cpp`: staged CPU search adapted from the macOS
  run. This is the fast engine.
- `run_all_candidates.ps1`: launches the fast engine once per candidate
  ciphertext, in parallel, and writes a combined summary.
- `src/enigma_cuda_prefix_filter.cu`: CUDA plugboard-feasibility prefix
  filter. It supports deeper exact prefixes up to the 17-character crib and
  writes survivor lists for CPU full solving. The GPU core-map cache is enabled
  by default; pass `--no-gpu-core-cache` to force the older arithmetic path.
- `run_mixed_length_gpu_prefix_benchmark.ps1`: mixed-length GPU prefix runner.
  Its defaults now use cached GPU core maps and direct survivor emission, so CPU
  verification can run without replaying the GPU filter.
- `run_gpu_hybrid_all_candidates.ps1`: GPU prefix filter plus parallel CPU
  full-solve runner for all default candidates. Its default prefix is now `13`,
  based on the 100M-state benchmark below.
- `run_gpu_hybrid_streaming_all_candidates.ps1`: chunked GPU prefix filtering
  with CPU full solving overlapped against the next GPU chunk. This remains a
  useful GPU-hybrid fallback.
- `run_behavior_direct_all_candidates.ps1`: direct exact behavior-class search
  based on initial electrical offsets plus middle/right turnover thresholds.
  This is currently the fastest measured exact path.
- `src/enigma_cuda_core_bench.cu`: CUDA feasibility benchmark for rotor-core
  generation. It is not an exact plugboard searcher.

`src/enigma_search.cpp` is a correctness-first single-process reference
implementation with built-in multi-candidate support, but it is much slower and
is not the recommended runner.

## Defaults

The default search is the literal expanded Tier 2 space:

- Reflectors: `B,C`
- Rotors: all permutations of `I,II,III,IV,V` taken three at a time
- Rings: `AAA` through `ZZZ`
- Starts/windows: `AAA` through `ZZZ`
- Plaintext: `REALITYISACONFLUX`
- Candidate ciphertexts: all 16 reader-side candidates supplied by the user,
  `#1` through `#16`, in preference order
- Max plugboard pairs: `10`
- Max results: unlimited

The plugboardless candidate `#16` (`ZYRYRZWJUFPDYKEGB`) is treated as a real candidate,
but it does not stop the default run. The search prints each verified solution
as soon as it is found and keeps going unless you explicitly pass
`--max-results`.

## Installed on this PC

Installed during this run:

- Visual Studio Build Tools 2022 with the C++ workload.
- CMake 4.3.3.
- NVIDIA CUDA Toolkit 13.3.

The commands used were:

```powershell
winget install --source winget --id Microsoft.VisualStudio.2022.BuildTools --exact --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
winget install --source winget --id Nvidia.CUDA --exact
winget install --source winget --id Kitware.CMake --exact
```

## Build

### Visual Studio Developer PowerShell

```powershell
cd C:\Users\xkell\Documents\Codex\enigma_search
cl /std:c++17 /O2 /EHsc /DNDEBUG src\enigma_m3_search_fast.cpp /Fe:enigma_m3_search_fast.exe
```

From a normal PowerShell session:

```powershell
cmd.exe /d /s /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && cl /std:c++17 /O2 /EHsc /DNDEBUG src\enigma_m3_search_fast.cpp /Fe:enigma_m3_search_fast.exe'
```

Build the CUDA core benchmark:

```powershell
cmd.exe /d /s /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.3\bin\nvcc.exe" -O3 -arch=sm_89 src\enigma_cuda_core_bench.cu -o enigma_cuda_core_bench.exe'
```

Build the CUDA prefix filter:

```powershell
cmd.exe /d /s /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.3\bin\nvcc.exe" -O3 -arch=sm_89 src\enigma_cuda_prefix_filter.cu -o enigma_cuda_prefix_filter.exe'
```

## Correctness checks

```powershell
.\enigma_m3_search_fast.exe --self-test
.\enigma_m3_search_fast.exe --tier 1 --plaintext THEDEATHWASERASED --ciphertext ZYZYFVWJUFEXKGPOB --threads 1 --start-index 202057998 --max-states 1 --max-results 1 --progress-seconds 0 --skip-initial-tests --output reader_known_pc_check.json
```

The self-test verifies:

- reader settings encrypt `THEDEATHWASERASED` to `ZYZYFVWJUFEXKGPOB`
- reader settings decrypt that ciphertext back to the plaintext
- same-position plaintext/ciphertext pairs are rejected
- a targeted literal search at the reader state finds a valid solution
- any found solution is verified by full Enigma encryption

## Benchmark Results

Hardware:

- CPU: AMD Ryzen 9 7950X3D, 16 cores / 32 logical processors.
- GPU: NVIDIA GeForce RTX 4090.

Measured on this PC. Rows that mention the 8-candidate set were collected before
the default candidate list was expanded to 16 entries.

| Runner | Work | Wall Time | Rate | Notes |
| --- | ---: | ---: | ---: | --- |
| `enigma_m3_search_fast.exe` | 10M states, one candidate, 32 threads | 2.005s | 4.99M literal states/s | Exact staged CPU search |
| `enigma_m3_search_fast.exe` | 50M states, one candidate, 32 threads | 5.220s | 9.58M literal states/s | Exact staged CPU search |
| `run_all_candidates.ps1` | 10M states against old 8-candidate set, 4 threads/candidate | 9.942s | 1.01M full eight-cipher literal states/s | 80M candidate-state checks total |
| ad hoc parallel 8-candidate run | 50M states against old 8-candidate set, 4 threads/candidate | 42.308s | 1.18M full eight-cipher literal states/s | 400M candidate-state checks total |
| `enigma_cuda_core_bench.exe` | 50M states, rotor/core-map generation only | 0.676s | 74.0M core-map states/s | Not an exact plugboard search |
| GPU prefix + CPU full solve | 50M states, one candidate | 3.123s internal | 16.0M literal states/s | Exact hybrid: 1.636s GPU prefix + 1.487s CPU full |
| `run_gpu_hybrid_all_candidates.ps1` | 10M states against old 8-candidate set | 3.400s | 2.94M full eight-cipher literal states/s | Exact hybrid, 80M candidate-state checks |
| `run_gpu_hybrid_all_candidates.ps1 -PrefixLen 10` | 100M states against old 8-candidate set | 21.406s | 4.67M full eight-cipher literal states/s | Exact hybrid, 800M candidate-state checks |
| `run_gpu_hybrid_all_candidates.ps1 -PrefixLen 11` | 100M states against old 8-candidate set | 12.149s | 8.23M full eight-cipher literal states/s | Deeper exact GPU prefix |
| `run_gpu_hybrid_all_candidates.ps1 -PrefixLen 12` | 100M states against old 8-candidate set | 10.072s | 9.93M full eight-cipher literal states/s | Deeper exact GPU prefix |
| `run_gpu_hybrid_all_candidates.ps1 -PrefixLen 13` | 100M states against old 8-candidate set | 9.866s | 10.14M full eight-cipher literal states/s | Best measured hybrid setting |
| `run_gpu_hybrid_all_candidates.ps1 -PrefixLen 14` | 100M states against old 8-candidate set | 10.219s | 9.79M full eight-cipher literal states/s | Slightly slower than prefix 13 |
| `run_gpu_hybrid_all_candidates.ps1 -PrefixLen 17` | 100M states against old 8-candidate set | 11.837s | 8.45M full eight-cipher literal states/s | Full-prefix GPU filter, slower than prefix 13 |
| `run_gpu_hybrid_streaming_all_candidates.ps1 -PrefixLen 13 -ChunkStates 100M` | 200M states against old 8-candidate set | 18.637s | 10.73M full eight-cipher literal states/s | Streaming overlap, two 100M chunks |
| `enigma_m3_search_fast.exe --behavior-compressed` | 50M states, one candidate | 8.872s | 5.64M literal states/s | Exact behavior compression experiment, not adopted |
| `enigma_m3_search_fast.exe --behavior-compressed` | 200M states, one candidate | 34.742s | 5.76M literal states/s | Larger compression test; bucket build still dominated |
| `enigma_m3_search_fast.exe --behavior-direct` | 10M behavior classes, one candidate | 1.416s | 734M literal-equivalent states/s | Direct exact behavior classes, no scan/dedup build |
| `run_behavior_direct_all_candidates.ps1` | 10M behavior classes against old 8-candidate set | 12.058s | 86.25M full eight-cipher literal-equivalent states/s | Direct exact behavior classes, stage 1/5 skipped |
| `run_behavior_direct_all_candidates.ps1` | 50M behavior classes against old 8-candidate set | 60.000s | 86.67M full eight-cipher literal-equivalent states/s | Before stage 1/5 skip; still representative |
| Cached CUDA prefix filter | 10M behavior classes, 288 actual 14-char targets | 17.68s total | 162.9M behavior-target checks/s including cache build | Survivor counts matched arithmetic path exactly |
| `run_phrase_pair_first.ps1` | 10M behavior classes, all 25 14-char phrase pairs | 171.5s | 98.3M behavior-target checks/s | Found and CPU-verified all 25/25 phrase pairs in first chunk |

The correctness-first single-process multi-candidate reference
`enigma_search.exe` measured about `252k` states/s for 10M states and the old
8-candidate set, so it is not recommended for full Tier 2.

## Benchmark Commands

```powershell
.\enigma_m3_search_fast.exe --tier 2 --plaintext REALITYISACONFLUX --ciphertext ZYZYFVWJUFEXKGPOB --threads 32 --max-states 10000000 --progress-seconds 2 --skip-initial-tests --output fast_cpu_10m_single.json
```

All default candidates, exact CPU search:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run_all_candidates.ps1 -MaxStates 10000000 -ThreadsPerCandidate 4 -ProgressSeconds 0 -OutputDir .\outputs_10m_all_candidates -SummaryPath .\all_candidates_10m_summary.json
```

All default candidates, exact GPU-filter/CPU-full hybrid:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run_gpu_hybrid_all_candidates.ps1 -MaxStates 10000000 -ThreadsPerCandidate 4 -WorkDir .\gpu_hybrid_10m_all -SummaryPath .\gpu_hybrid_10m_all_summary.json
```

To compare prefix depths explicitly:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run_gpu_hybrid_all_candidates.ps1 -MaxStates 100000000 -PrefixLen 13 -ThreadsPerCandidate 4 -WorkDir .\gpu_hybrid_100m_all_prefix13 -SummaryPath .\gpu_hybrid_100m_all_prefix13_summary.json
```

CUDA core-map benchmark:

```powershell
.\enigma_cuda_core_bench.exe 50000000 0
```

CUDA prefix filter for one candidate:

```powershell
.\enigma_cuda_prefix_filter.exe --tier 2 --plaintext REALITYISACONFLUX --ciphertext ZYZYFVWJUFEXKGPOB --max-states 50000000 --survivor-dir .\gpu_survivors_50m --output gpu_prefix_50m_single_c8_with_survivors.json
.\enigma_m3_search_fast.exe --tier 2 --plaintext REALITYISACONFLUX --ciphertext ZYZYFVWJUFEXKGPOB --threads 32 --state-list-binary .\gpu_survivors_50m\candidate_0_survivors.bin --progress-seconds 0 --skip-initial-tests --output hybrid_fullsolve_50m_single_c8.json
```

Phrase-pair-first story clue run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run_phrase_pair_first.ps1 -ReaderPlaintextsPath .\story_clue_reader_plaintexts_14_only.txt -GordonPlaintextsPath .\story_clue_gordon_plaintexts_14_only.txt -WorkDir .\phrase_pair_first_14 -SummaryPath .\phrase_pair_first_14_summary.json
```

## Full default Tier 2 run

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run_all_candidates.ps1 -ThreadsPerCandidate 4 -ProgressSeconds 30 -OutputDir .\outputs_full_tier2 -SummaryPath .\all_candidates_full_tier2_summary.json
```

Recommended full Tier 2 run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run_behavior_direct_all_candidates.ps1 -ThreadsPerCandidate 4 -ProgressSeconds 30 -OutputDir .\behavior_direct_full_tier2 -SummaryPath .\behavior_direct_full_tier2_summary.json
```

Recommended GPU-hybrid full Tier 2 fallback:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run_gpu_hybrid_streaming_all_candidates.ps1 -ChunkStates 100000000 -PrefixLen 13 -ThreadsPerCandidate 4 -ProgressSeconds 30 -WorkDir .\gpu_hybrid_full_tier2_streaming -SummaryPath .\gpu_hybrid_full_tier2_streaming_summary.json
```

Resume from a literal state index for all candidates:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run_all_candidates.ps1 -StartIndex 1234567890 -ThreadsPerCandidate 4 -ProgressSeconds 30 -OutputDir .\outputs_resume -SummaryPath .\all_candidates_resume_summary.json
```

Tier 1 fixed rotor order `III,I,IV` for all candidates:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run_all_candidates.ps1 -Tier 1 -ThreadsPerCandidate 4 -ProgressSeconds 30 -OutputDir .\outputs_tier1 -SummaryPath .\all_candidates_tier1_summary.json
```

## Candidate list

Default candidates:

| ID | Active plugboard pairs | Ciphertext |
| --- | --- | --- |
| 1 | `PE AF GR` | `ZYZYFVWJUFEXKGPOB` |
| 2 | `PE GR UT` | `JYZYAZGJTFEXKKPOB` |
| 3 | `PE AF UT` | `JYZYFVRJTFEXYRPOB` |
| 4 | `AF GR UT` | `JYGYGVGJTFPDKGERB` |
| 5 | `PE AF GR UT` | `JYZYFVGJTFEXKGPOB` |
| 6 | `PE GR` | `ZYZYAZWJUFEXKKPOB` |
| 7 | `PE AF` | `ZYZYFVWJUFEXYRPOB` |
| 8 | `PE UT` | `JYZYAZRJTFEXYKPOB` |
| 9 | `AF GR` | `ZYGYGVWJUFPDKGERB` |
| 10 | `GR UT` | `JYGYGZGJTFPDKKERB` |
| 11 | `AF UT` | `JYRYRVRJTFPDYREGB` |
| 12 | `PE` | `ZYZYAZWJUFEXYKPOB` |
| 13 | `GR` | `ZYGYGZWJUFPDKKERB` |
| 14 | `AF` | `ZYRYRVWJUFPDYREGB` |
| 15 | `UT` | `JYRYRZRJTFPDYKEGB` |
| 16 | none | `ZYRYRZWJUFPDYKEGB` |

The recommended runner includes candidate `#16` by design. For a comparison run
without it, remove that entry from the runner script or use the slower
reference executable's `--exclude-plugboardless-candidate` option.

## GPU Evaluation

CUDA is installed and works. Two GPU tests were built:

- `enigma_cuda_core_bench.exe`: rotor/core-map generation only, about `74M`
  states/s on 50M states.
- `enigma_cuda_prefix_filter.exe`: exact plugboard-feasibility prefix filter.

The prefix filter is useful. At prefix 10 it matched the CPU stage-10 survivor
counts on benchmarked slices, and deeper prefixes sped up exact search when
paired with CPU full solving:

- 50M single-candidate exact CPU: `5.220s`.
- 50M single-candidate GPU prefix + CPU full solve: `3.123s` internal timing.
- 10M all-eight exact CPU runner: `9.942s`.
- 10M all-eight GPU prefix + CPU full solve: `3.400s`.
- 100M all-eight GPU prefix 13 + CPU full solve: `9.866s`.

This is still a hybrid, not a full GPU solver: the GPU does the broad exact
prefix filter, and the CPU does the branch-heavy full plugboard solve for
survivors.

The old scan-and-deduplicate behavior compression experiment is not adopted:

- `--behavior-compressed` is exact, but it scans literal states to discover
  behavior buckets, so bucket construction dominates the run.
- `--behavior-direct` is the useful version. It directly enumerates behavior
  classes without scanning, and expands any hit back to all 26 literal
  ring/start states.
- A combined eight-candidate CUDA kernel was disabled because it did not match
  exact survivor counts in validation.
