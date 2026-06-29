# Enigma Search Handoff For Next-Step Planning

This file is intended to be pasted into a fresh ChatGPT conversation to help formulate next steps after a full exact Enigma search returned no solutions.

## Executive Summary

We are searching for Gordon-side Enigma M3 settings that encrypt:

```text
REALITYISACONFLUX
```

to one of 16 reader-side ciphertexts derived from possible active plugboard pairs. The latest full exact scan searched every Tier 2 M3 state under the current assumptions for all 16 ciphertexts and found:

```text
0 solutions
```

If the implementation and ciphertext assumptions are correct, the result means there is no solution in the searched space:

- Reflectors: B, C
- Rotors: all 3-rotor permutations from I, II, III, IV, V
- Rings: AAA through ZZZ
- Starts/windows: AAA through ZZZ
- Plugboard: solved exactly as constraints, up to 10 plugboard pairs
- Plaintext crib: REALITYISACONFLUX
- Candidate ciphertexts: 16 reader-side strings listed below

The practical implication is that rerunning the same search space is unlikely to help. The next useful work is either cross-validation of exactness/input generation or expansion/change of assumptions.

## Current Candidate Ciphertexts

These are sorted in desired preference order. Result reporting preserves this order.

| ID | Active reader-side plugboard pairs | Ciphertext |
| ---: | --- | --- |
| 1 | PE AF GR | ZYZYFVWJUFEXKGPOB |
| 2 | PE GR UT | JYZYAZGJTFEXKKPOB |
| 3 | PE AF UT | JYZYFVRJTFEXYRPOB |
| 4 | AF GR UT | JYGYGVGJTFPDKGERB |
| 5 | PE AF GR UT | JYZYFVGJTFEXKGPOB |
| 6 | PE GR | ZYZYAZWJUFEXKKPOB |
| 7 | PE AF | ZYZYFVWJUFEXYRPOB |
| 8 | PE UT | JYZYAZRJTFEXYKPOB |
| 9 | AF GR | ZYGYGVWJUFPDKGERB |
| 10 | GR UT | JYGYGZGJTFPDKKERB |
| 11 | AF UT | JYRYRVRJTFPDYREGB |
| 12 | PE | ZYZYAZWJUFEXYKPOB |
| 13 | GR | ZYGYGZWJUFPDKKERB |
| 14 | AF | ZYRYRVWJUFPDYREGB |
| 15 | UT | JYRYRZRJTFPDYKEGB |
| 16 | none | ZYRYRZWJUFPDYKEGB |

Preference rules behind this order:

- Pair importance: PE > GR > AF > UT
- Active-pair-count importance: 3 pairs > 4 pairs > 2 pairs > 1 pair > 0 pairs

## Latest Full Scan Result

Run path:

```text
C:\Users\xkell\Documents\Codex\enigma_search
```

Command used:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run_behavior_direct_all_candidates.ps1 -ThreadsPerCandidate 2 -ProgressSeconds 60 -OutputDir .\behavior_direct_full_16_20260628_230130 -SummaryPath .\behavior_direct_full_16_20260628_230130.json
```

Output files:

```text
behavior_direct_full_16_20260628_230130.json
behavior_direct_full_16_20260628_230130\
behavior_direct_full_16_20260628_230130.out.txt
behavior_direct_full_16_20260628_230130.err.txt
```

Full-run metrics:

| Metric | Value |
| --- | ---: |
| Candidate count | 16 |
| Behavior classes per candidate | 356,441,280 |
| Literal states represented per candidate | 37,069,893,120 |
| Aggregate literal-equivalent states | 593,118,289,920 |
| Wall time | 723.1977832 seconds, about 12m 03s |
| Aggregate literal-equivalent rate | 820,132,892.686 checks/sec |
| Ordered solutions | 0 |
| Total results | 0 |
| stderr | Clean |

Candidate-level result counts:

| ID | Label | Result count | Runtime sec | Full solves |
| ---: | --- | ---: | ---: | ---: |
| 1 | PE AF GR | 0 | 720.009 | 20,149,933 |
| 2 | PE GR UT | 0 | 480.008 | 7,030,949 |
| 3 | PE AF UT | 0 | 480.006 | 6,197,681 |
| 4 | AF GR UT | 0 | 480.006 | 6,173,822 |
| 5 | PE AF GR UT | 0 | 720.005 | 15,674,426 |
| 6 | PE GR | 0 | 480.008 | 12,043,661 |
| 7 | PE AF | 0 | 720.007 | 20,149,933 |
| 8 | PE UT | 0 | 480.011 | 2,447,342 |
| 9 | AF GR | 0 | 720.009 | 32,366,272 |
| 10 | GR UT | 0 | 480.006 | 6,120,427 |
| 11 | AF UT | 0 | 420.007 | 1,741,502 |
| 12 | PE | 0 | 540.007 | 12,043,661 |
| 13 | GR | 0 | 720.009 | 25,261,371 |
| 14 | AF | 0 | 540.006 | 20,063,194 |
| 15 | UT | 0 | 480.008 | 1,740,257 |
| 16 | none | 0 | 480.007 | 12,013,614 |

The PC was pinned at 100 percent all-core load during the run. Reported CPU package temperature was about 79.25 C, which appeared stable.

## Search Implementations In The Repo

Primary project folder:

```text
C:\Users\xkell\Documents\Codex\enigma_search
```

Important files:

| File | Purpose |
| --- | --- |
| src\enigma_m3_search_fast.cpp | Main fast exact search engine. Supports literal expanded search, GPU survivor-list full solving, behavior-compressed, and behavior-direct modes. |
| run_behavior_direct_all_candidates.ps1 | Current fastest full-run wrapper. Launches one fast-engine process per candidate. |
| run_all_candidates.ps1 | Literal expanded CPU all-candidate wrapper. Slower fallback. |
| src\enigma_cuda_prefix_filter.cu | CUDA exact prefix filter. Useful for GPU-hybrid filtering but not currently fastest for full exact search. |
| run_gpu_hybrid_all_candidates.ps1 | Non-streaming GPU prefix filter plus CPU full solve. |
| run_gpu_hybrid_streaming_all_candidates.ps1 | Streaming GPU prefix filter plus CPU full solve overlap. |
| src\enigma_search.cpp | Slower correctness-first reference implementation with multi-candidate support. |
| README.md | Build notes, benchmark notes, candidate table, and run commands. |

The current recommended exact path is `run_behavior_direct_all_candidates.ps1`.

## Exactness Notes

The behavior-direct method is intended to be exact, not sampled.

ELI5 version: many different ring/start settings cause the Enigma rotors to behave identically for this 17-letter crib. Instead of testing all 104 literal settings in such a group one by one, the code tests one behavior class and then expands any hit back to the represented literal settings. It should not discard a possible solution if the behavior-class grouping is correct.

Known correctness checks already performed:

- Fast engine self-test passed.
- Reference engine self-test passed.
- Reader known-state checks passed for the known reader example.
- CUDA default candidate order check passed after the 16-cipher update.
- Behavior-direct, GPU-hybrid, and streaming-hybrid one-state 16-candidate smoke checks passed.
- The full 16-candidate behavior-direct run completed cleanly with no stderr.

Important caveat: because the final result was zero, it is still worth doing one more independent cross-validation pass before expanding the search space too far. Good validation would include comparing behavior-direct against literal expanded search for deterministic slices and/or generating artificial known Gordon-side hits for `REALITYISACONFLUX`.

## Performance History

Useful prior benchmark numbers on this PC:

| Method | Work | Result |
| --- | --- | --- |
| Fast CPU literal, one candidate | 50M states | about 9.58M literal states/sec |
| GPU prefix plus CPU full solve | 100M states, old 8-candidate set, prefix 13 | about 10.14M full eight-cipher literal states/sec |
| Streaming GPU hybrid | 200M states, old 8-candidate set, prefix 13 | about 10.73M full eight-cipher literal states/sec |
| Behavior-direct, old 8-candidate set | 50M behavior classes each | about 86.67M full eight-cipher literal-equivalent states/sec |
| Behavior-direct, current 16-candidate full scan | 593.1B literal-equivalent states | about 820M aggregate literal-equivalent checks/sec |

The 16-candidate full run used `ThreadsPerCandidate = 2`, giving 32 total worker threads on the Ryzen 9 7950X3D. This was chosen to match the CPU's 32 logical processors.

## Interpretation Of The Zero-Solution Result

Under the current assumptions, a full exact scan found no settings. The most likely next-step categories are:

1. Verify the inputs.
2. Verify the exactness of the accelerated behavior-direct search with independent checks.
3. Expand or alter Enigma assumptions.
4. Reconsider the crib/plaintext/ciphertext relationship.

It is probably not useful to rerun the same full 16-candidate Tier 2 search unchanged.

## Recommended Next Steps

### 1. Re-derive the 16 reader-side ciphertexts independently

Before expanding the search space, confirm the 16 ciphertexts are exactly what the reader-side setup should produce.

Specific checks:

- Recompute all 16 ciphertexts from the assumed reader settings and active pairs.
- Confirm pair notation direction is irrelevant and normalized, e.g. PE equals EP.
- Confirm `UT` was applied exactly as intended.
- Confirm no plaintext/ciphertext was copied with a typo.
- Confirm the reader plaintext used to derive these ciphers is the intended reader-side plaintext, not the Gordon plaintext.

Why this matters: a single wrong letter in the candidate table can make the correct Gordon-side solution impossible to find.

### 2. Create artificial known Gordon-side hits for REALITYISACONFLUX

Generate several ciphertexts by choosing known Gordon settings and encrypting `REALITYISACONFLUX`, then verify the search recovers them.

Useful artificial tests:

- Known hit with no plugboard.
- Known hit with 3 plugboard pairs.
- Known hit with 10 plugboard pairs.
- Known hit whose ring/start falls into a behavior class that is not the first literal representative.

This directly tests whether the fast search can find known answers for the exact target plaintext length and target string.

### 3. Cross-check behavior-direct against literal expanded search on deterministic slices

Choose several literal state windows and run both:

- literal expanded `enigma_m3_search_fast.exe`
- `--behavior-direct`

Compare result counts and, where practical, stage/full-solve counts. Include windows near rotor turnover boundaries, because behavior compression depends on turnover behavior.

This is the fastest way to build confidence that the zero-result full scan is a real negative rather than an acceleration bug.

### 4. Expand rotor and reflector assumptions

Current Tier 2 searches only rotors I-V and reflectors B,C. If those assumptions are too narrow, expand in stages.

Possible staged expansions:

| Expansion | Approximate multiplier | Notes |
| --- | ---: | --- |
| Add reflector A | 1.5x | Search B,C currently; A/B/C would be 3 reflectors instead of 2. |
| Add rotors VI, VII, VIII | 5.6x | Rotor permutations go from 5P3 = 60 to 8P3 = 336. |
| Add both reflector A and rotors VI-VIII | 8.4x | Still likely feasible with behavior-direct if implemented cleanly. |
| Explore M4/Beta/Gamma assumptions | Larger | Only if there is reason to suspect Naval/M4-style settings. |

If doing this, implement and test one expansion at a time.

### 5. Reconsider the target plaintext

The target Gordon plaintext is currently:

```text
REALITYISACONFLUX
```

Questions to verify:

- Is this exactly 17 letters with no omitted filler?
- Is `CONFLUX` definitely correct?
- Could the intended plaintext have a filler letter, alternate spelling, or transposition?
- Is the Gordon-side plaintext known to align exactly with these reader-side ciphertexts?
- Could encryption direction or message alignment be offset?

Enigma encryption is reciprocal, so encrypt/decrypt direction does not matter, but alignment and exact text do.

### 6. Consider plugboard pair-count assumptions only after the above

The solver currently allows up to 10 plugboard pairs, matching normal wartime Enigma practice. If this puzzle may use a non-historical plugboard with more than 10 pairs, try raising the limit toward 13. This may increase solve complexity, and it should be treated as lower priority than verifying inputs and expanding rotor/reflector assumptions.

### 7. Improve reporting for future negative runs

The current result is usable, but future runs would be easier to audit if the summary included:

- explicit `searched_space` object listing reflectors, rotor set, ring/start ranges, max plugboard pairs
- code build hash or source timestamp
- per-candidate preference rank
- per-candidate negative proof statement
- exact command-line used
- CPU temperature/throttling note if manually observed

## Suggested Prompt For A Fresh ChatGPT Session

Paste this file and ask:

```text
Given this Enigma search handoff, help me decide the highest-value next steps. I want to avoid rerunning the same exact search space. Prioritize ways to distinguish between input mistakes, search implementation mistakes, and wrong Enigma assumptions. Give me a concrete test plan with expected costs and what each outcome would imply.
```

## Bottom Line

The current exact search was broad within its assumptions and found no solution. The most rational next move is not more brute force in the same space. The best next move is a short validation battery:

1. independently regenerate the 16 ciphertexts,
2. create known-hit tests for `REALITYISACONFLUX`,
3. cross-check behavior-direct against literal search on turnover-heavy slices,
4. then expand assumptions such as reflector A and rotors VI-VIII if validation passes.
