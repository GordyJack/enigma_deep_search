# Enigma Search Improvement Exploration

Generated: 2026-06-29

## Scope

This report covers the exact-search improvement routes requested after the
historical visible-notch turnover correction.

Hard assumptions were preserved:

- Reader plaintext remains `THEDEATHWASERASED`.
- Gordon plaintext target list remains the existing 8-item list.
- Reflectors remain B/C only.
- Rotors remain I-V only.
- No M4/Beta/Gamma expansion.
- Plugboard limit was not raised.
- Turnover uses standard visible notch letters; rings affect wiring offset only.

Current target set:

- Total target pairings: 768
- Impossible by no-self-encryption: 344
- Viable pairings: 424

## Route 1: Bombe/Menu-Style Plugboard Solver

Status: already strong; no rewrite adopted.

Files inspected:

- `src/enigma_m3_search_fast.cpp`

Findings:

- `CribProblem` builds bidirectional relations for each prefix length.
- The solver models equations equivalent to `C = P(Core(P(G)))`.
- `PlugSolver::assign_with_involution` enforces plugboard symmetry immediately.
- `PlugSolver::propagate_assignment` propagates each assignment through all graph relations immediately.
- Contradictions are rejected during propagation.
- Fixed points are allowed and do not count as plugboard pairs.
- The maximum plugboard-pair limit is enforced during assignment.
- Every emitted candidate is still verified by actual Enigma encryption before being reported.

Decision:

- Keep current solver as default.
- Do not rewrite until a prototype proves faster on deterministic slices.

## Route 2: Diagonal-Board/Reciprocal Propagation

Status: already present.

Findings:

- Reciprocal plugboard assignment is explicit: assigning `A -> B` also assigns `B -> A`.
- Attempts to plug one letter to two different letters fail immediately.
- Assignments are queued and propagated through graph relations until the queue is empty or a contradiction appears.

Decision:

- No change adopted. Current implementation already has the important reciprocal propagation behavior.

## Route 3: Batch Viable Pairings Per Machine State

Status: not adopted yet.

Findings:

- The current CPU runner still effectively searches target-by-target.
- A true "compute one behavior state, test many targets" structure could reduce repeated rotor/core work.
- The previous combined GPU candidate kernel is still unsafe: it produced mismatched survivor counts when more than one target was active.

Decision:

- Do not make batching default yet.
- Future batching must match exact CPU results on deterministic slices before use.

## Route 4: GPU Prefix/Full-Crib Filtering

Status: promising optional path; not default until more validation and runner integration.

Files changed:

- `src/enigma_cuda_prefix_filter.cu`
- `src/enigma_m3_search_fast.cpp`
- `run_gpu_behavior_prefix_all_candidates.ps1`

Implemented:

- Added CUDA `--behavior-direct` mode that scans corrected 26x behavior classes rather than literal ring/start states.
- Added CPU `--behavior-class-list-binary` mode so GPU survivor behavior-class IDs can be verified by the existing exact CPU solver.
- Kept old combined-candidate CUDA kernel disabled because it failed exact survivor-count validation.

Correctness checks performed:

- Existing validation battery: pass.
- GPU prefix-10 behavior survivor count matched CPU behavior-direct on a 1M-class deterministic slice:
  - GPU survivors: 134,344
  - CPU stage10 survivors: 134,344
- Artificial known-hit window:
  - GPU prefix 13 preserved known class `767044364`.
  - GPU prefix 17 preserved known class `767044364`.
  - CPU verifier recovered verified Enigma solutions from the GPU survivor list.
- Deterministic hit-window result parity:
  - CPU behavior-direct results: 4
  - GPU prefix-17 + CPU verifier results: 4

Single-target benchmark, 1M behavior classes, target `REALITYISACONFLUX` -> `BODZZCLWVQYKDVRAV`:

| Prefix | GPU Kernel Seconds | Survivors | Survivor Rate | Total GPU+CPU Wall |
|---:|---:|---:|---:|---:|
| 5 | 0.0051 | 1,000,000 | 100.0000% | 1.84s |
| 6 | 0.0070 | 1,000,000 | 100.0000% | 1.80s |
| 7 | 0.0112 | 999,935 | 99.9935% | 1.80s |
| 8 | 0.0234 | 948,069 | 94.8069% | 1.78s |
| 9 | 0.0482 | 620,023 | 62.0023% | 1.64s |
| 10 | 0.0607 | 134,344 | 13.4344% | 1.45s |
| 11 | 0.0522 | 7,798 | 0.7798% | 1.39s |
| 12 | 0.0360 | 564 | 0.0564% | 1.30s |
| 13 | 0.0150 | 6 | 0.0006% | 1.29s |
| 14 | 0.0142 | 0 | 0.0000% | 1.32s |
| 15 | 0.0126 | 0 | 0.0000% | 1.28s |
| 16 | 0.0131 | 0 | 0.0000% | 1.28s |
| 17 | 0.0142 | 0 | 0.0000% | 1.31s |

Single-target benchmark, 10M behavior classes:

| Prefix | GPU Kernel Seconds | Survivors | Survivor Rate |
|---:|---:|---:|---:|
| 9 | 0.4702 | 6,203,988 | 62.0399% |
| 10 | 0.6065 | 1,344,186 | 13.4419% |
| 17 | 0.1317 | 0 | 0.0000% |

All viable pairings sample:

- Prefix: 17
- Classes per viable target: 1,000,000
- Viable targets tested: 424
- Total behavior-target checks: 424,000,000
- Total survivors: 0
- Wall time across 8 Gordon plaintext groups: 8.01s
- Aggregate wall rate: about 52.9M behavior-target checks/sec

Grouped runner 50M speed check:

- Runner: `run_gpu_behavior_prefix_all_candidates.ps1`
- Prefix: 17
- Behavior classes per viable target: 50,000,000
- Viable targets: 424
- Impossible targets skipped: 344
- Total behavior-target checks: 21,200,000,000
- Total GPU survivors in this slice: 0
- Ordered solutions in this slice: 0
- Wall time: 277.99s
- Aggregate behavior-target checks/sec: about 76.3M/s
- Estimated full prefix-17 GPU prefilter over the selected 424 viable pairings: about 2.20 hours

Grouped runner 50M counts-first speed check:

- Runner: `run_gpu_behavior_prefix_all_candidates.ps1`
- Mode: count-only first; survivor replay only for nonzero counts
- Prefix: 17
- Behavior classes per viable target: 50,000,000
- Viable targets: 424
- Impossible targets skipped: 344
- Total behavior-target checks: 21,200,000,000
- Total GPU survivors in this slice: 0
- Ordered solutions in this slice: 0
- Wall time: 275.81s
- Aggregate behavior-target checks/sec: about 76.9M/s
- Estimated full prefix-17 GPU prefilter over the selected 424 viable pairings: about 2.18 hours

Counts-first known-survivor validation:

- Known class window: class `767044364`, 11 behavior classes
- Count-only survivors: 1
- Replay survivors: 1
- CPU verified results: 1+
- Status: pass

Experimental combined batching validation:

- Prototype: `--combined-candidates --allow-experimental-combined`
- Test: 8 viable Gordon-rank-1 targets, 1M behavior classes, prefix 10
- Result: rejected
- Reason: every nonzero survivor count mismatched the trusted sequential GPU path.
- Timing was also slower than sequential in this slice.

Estimated full GPU prefix-17 prefilter over all 424 viable pairings:

- Behavior classes per target: 1,425,765,120
- Total behavior-target checks: 604,524,410,880
- Estimate from 1M all-target sample: about 3.2 hours
- Estimate from 50M grouped runner sample: about 2.2 hours
- Estimate from 50M counts-first grouped runner sample: about 2.18 hours

CPU-only baseline:

- Previous corrected CPU behavior-direct estimates were roughly 24-52 hours depending on extrapolation method and parallel contention.
- GPU prefix-17 looks materially faster, but still not yet <30 minutes.

Decision:

- Keep CPU behavior-direct as safe fallback.
- Treat GPU prefix-17 behavior filtering as the leading optional acceleration path.
- Do not make it default until a runner is added and deterministic slices around turnover boundaries are expanded.
- Keep counts-first as the preferred runner mode because it avoids survivor file churn when counts are zero and safely replays only nonzero targets.

## Route 5: Menu-Strength Diagnostics

Status: added as diagnostics only.

Files changed:

- `analyze_target_menus.ps1`

Output:

- `target_menu_diagnostics.json`

What it computes:

- Viable/impossible split.
- Menu graph edges and active nodes.
- Connected component sizes.
- Cycle rank.
- Max graph degree.
- Repeated plaintext/ciphertext letters.
- Diagnostic strength score.

Important:

- This does not affect final result ordering.
- Final ordering remains reader rank, Gordon plaintext rank, machine-setting tie-breakers.

Initial result:

- Viable pairings: 424
- Impossible pairings: 344
- Strongest example: reader 88 / Gordon 7 / score 487
- Weakest example: reader 20 / Gordon 1 / score 91

Decision:

- Keep as optional reporting and planning aid.

## Route 6: Hill Climbing / Near-Miss Diagnostics

Status: not implemented.

Decision:

- Do not add now.
- It is not needed for exact known-plaintext solving.
- If added later, keep behind an explicit diagnostic flag and label outputs as non-proof heuristic near misses.

## Current Recommendation

Default path:

- Keep CPU behavior-direct exact search as fallback/default for trusted correctness.

Most promising acceleration:

- GPU behavior-direct prefix/full-crib filtering with prefix 17, followed by CPU verification of survivor behavior classes.

Rejected for default:

- Combined multi-candidate GPU kernel, because survivor counts mismatched exact sequential GPU/CPU validation.
- Solver rewrite, because the current solver is already menu/diagonal-board-like and validated.

Next work:

1. Add resume/checkpointing to the GPU behavior-prefix runner.
2. Preserve final result ordering separately from GPU scheduling.
3. Add deterministic turnover-boundary GPU/CPU slice comparisons.
4. Benchmark larger chunks, likely 100M+ behavior classes per target group, before estimating full-run time more confidently.
