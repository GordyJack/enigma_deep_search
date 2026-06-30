# MINDORDERCHAOS Staged Literal Expansion

- Gordon match plaintext: `MINDORDERCHAOS`
- Display-facing Gordon text: `MIND+ORDER+CHAOS=REALITY`
- Full continuous Gordon plaintext: `MINDORDERCHAOSREALITY`
- Reader settings: reflector B, rotors III I IV, start GJM, rings MMM
- Reader plugboard option order: PE AF GR -> PE AF GR UT -> PE AF -> PE
- Gordon max active plugboard pairs: 4
- Stop threshold: 20 cumulative CPU-verified literal Gordon settings per reader phrase
- Total literal Gordon settings reported: 0
- Wall time: 102.916 seconds

## Reader Summary

| Reader plaintext | Cumulative settings | Tested options | Stopped at threshold | Incomplete | Ballooned |
| --- | ---: | ---: | --- | --- | --- |
| `MOMENTHIDDEATH` | 0 | 2 | False | False | False |
| `THEDAYHIDDEATH` | 0 | 2 | False | False | False |
| `SECRETLOOPDEAD` | 0 | 4 | False | False | False |
| `DEATHWASERASED` | 0 | 2 | False | False | False |
| `DEATHREWRITTEN` | 0 | 4 | False | False | False |
| `ONEYEARINWEEKS` | 0 | 4 | False | False | False |

## Option Counts

| Reader plaintext | Option | Reader ciphertext | GPU survivors | CPU-verified settings | Cumulative after option | Status |
| --- | --- | --- | ---: | ---: | ---: | --- |
| `MOMENTHIDDEATH` | 1 `PE AF GR` | `LHAUPWJTGOPLNJ` | 0 | 0 | 0 | complete |
| `MOMENTHIDDEATH` | 2 `PE AF GR UT` | `LHATPXJUGOPLLJ` | 0 | 0 | 0 | complete |
| `MOMENTHIDDEATH` | 3 `PE AF` | `LHAUPWJTROPLNJ` | 0 | 0 | 0 | skipped: same_position_impossible |
| `MOMENTHIDDEATH` | 4 `PE` | `LHFUPWJTROPMNJ` | 0 | 0 | 0 | skipped: same_position_impossible |
| `THEDAYHIDDEATH` | 1 `PE AF GR` | `BODZQMJTGOPLNJ` | 0 | 0 | 0 | complete |
| `THEDAYHIDDEATH` | 2 `PE AF GR UT` | `GODZQMJUGOPLLJ` | 0 | 0 | 0 | complete |
| `THEDAYHIDDEATH` | 3 `PE AF` | `BODZQMJTROPLNJ` | 0 | 0 | 0 | skipped: same_position_impossible |
| `THEDAYHIDDEATH` | 4 `PE` | `BODZOMJTROPMNJ` | 0 | 0 | 0 | skipped: same_position_impossible |
| `SECRETLOOPDEAD` | 1 `PE AF GR` | `OPHQZWTYFIFKIR` | 0 | 0 | 0 | complete |
| `SECRETLOOPDEAD` | 2 `PE AF GR UT` | `OPHQZXUYFIFKIR` | 0 | 0 | 0 | complete |
| `SECRETLOOPDEAD` | 3 `PE AF` | `OPHHZWTYFIFKIG` | 0 | 0 | 0 | complete |
| `SECRETLOOPDEAD` | 4 `PE` | `OPHHZWTYAIAKEG` | 0 | 0 | 0 | complete |
| `DEATHWASERASED` | 1 `PE AF GR` | `WPMBGTQXSCKRFR` | 0 | 0 | 0 | skipped: same_position_impossible |
| `DEATHWASERASED` | 2 `PE AF GR UT` | `WPMEGUQXSCKRFR` | 0 | 0 | 0 | skipped: same_position_impossible |
| `DEATHWASERASED` | 3 `PE AF` | `WPMBRTQXSHKGFG` | 0 | 0 | 0 | complete |
| `DEATHWASERASED` | 4 `PE` | `WPOBRTGXSHDGAG` | 0 | 0 | 0 | complete |
| `DEATHREWRITTEN` | 1 `PE AF GR` | `WPMBGPXHQPJGFC` | 0 | 0 | 0 | complete |
| `DEATHREWRITTEN` | 2 `PE AF GR UT` | `WPMEGPXHQPNWFC` | 0 | 0 | 0 | complete |
| `DEATHREWRITTEN` | 3 `PE AF` | `WPMBRSXHDPJRFC` | 0 | 0 | 0 | complete |
| `DEATHREWRITTEN` | 4 `PE` | `WPOBRSXHDPJRAC` | 0 | 0 | 0 | complete |
| `ONEYEARINWEEKS` | 1 `PE AF GR` | `SCDCZCFTXSPKZK` | 0 | 0 | 0 | complete |
| `ONEYEARINWEEKS` | 2 `PE AF GR UT` | `SCDCZCFUXSPKZK` | 0 | 0 | 0 | complete |
| `ONEYEARINWEEKS` | 3 `PE AF` | `SCDCZCKTXSPKZK` | 0 | 0 | 0 | complete |
| `ONEYEARINWEEKS` | 4 `PE` | `SCDCZKKTXSPKZK` | 0 | 0 | 0 | complete |

## Literal Settings

Full literal settings are included in `.\mindorderchaos_staged_expansion_max4_literal_settings.csv` and in the `literal_gordon_settings` array of `.\mindorderchaos_staged_expansion_max4_summary.json`.
Each row includes reflector, rotor order, start/window, rings, Gordon plugboard pairs, the first-14 ciphertext, the full continuous ciphertext, and the 7-letter `REALITY` suffix ciphertext.
