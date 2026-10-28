# WinDivert binaries

Not committed. The signed WinDivert 2.2 `WinDivert.dll`, `WinDivert64.sys` (and
`WinDivert.dll` import lib if building statically) are fetched here by
`scripts/fetch-windivert.ps1`, which verifies them against `SHA256SUMS`.

Why not committed: licensing/size, and the signed driver should come straight
from the upstream release. The build and installer copy these next to the
executables so the loader's `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` finds them
(ADR 002).

First run records the hashes into `SHA256SUMS`; commit that file so later runs
(and CI) verify the exact bytes.
