# Recon R5 implementation and validation report

Validated on Windows on 2026-10-17 using the existing project venv, Python 3.13.15 and PySide6 6.9.1. R5 implementation is complete; no subsequent scanner adapter or UI redesign was started.

## Preflight

- Branch: `bugfix/dec-20-pack`.
- HEAD remains `52ba30d6a2aa3758afe4ff7cde932af80648e16d` (`feat(recon): add import history and scraper handoff`).
- R4.1 was committed and the reported working tree was clean before changes.
- Baseline: `609 passed in 14.55s`, exit code 0.
- No commits, pushes, dependency additions, generated Qt UI edits or ScraperTaskManager changes.

## Files created and modified

| File | Change and purpose |
| --- | --- |
| `core/recon/windows_process.py` | New minimal Win32 Job Object process backend and executable image lock. |
| `core/recon/process_supervisor.py` | Select contained native Windows execution and preserve shared queue, lifecycle, output bounds and shutdown signals. |
| `core/recon/nmap_adapter.py` | New signed executable verification, fixed Nmap plans and trusted live XML compatibility handling. |
| `core/recon/execution_policy.py` | Add opaque, Nmap-specific one-use localhost authorization without changing domain scope decisions. |
| `core/recon/nmap_runtime.py` | New explicit setup/run/stop controller and atomic import into the existing inventory. |
| `ui/panels/recon_tab.py` | Extend the existing Tool Manager Nmap row and refresh existing inventory/history after successful runs. |
| `tests/conftest.py` | Prohibit native process launches by default; narrowly allow the harmless Windows integration fixture. |
| `tests/core/recon/test_windows_process.py` | New real Windows lifecycle, tree cleanup, containment failure, output and executable lock tests. |
| `tests/fixtures/recon_process.py` | New harmless local process fixture; no network behavior. |
| `tests/core/recon/test_nmap_adapter.py` | New executable trust, authorization, immutable arguments, XML and static image lock regressions. |
| `tests/core/recon/test_nmap_runtime.py` | New inventory/history preservation, successful/zero-open imports, setup, stop and failure tests. |
| `tests/ui/panels/test_recon_nmap_live.py` | New Tool Manager action, confirmation, status and inventory refresh tests using controlled runtime results. |
| `tests/ui/panels/test_recon_tab.py` | Update the R4 expectation that no live-tool controls exist; require initially disabled R5 controls. |
| `tests/ui/test_recon_integration.py` | Update R4 setup/control expectations while preserving Scraper and offline workflows. |
| `docs/recon_nmap_live.md` | New adapter behavior, trust, XML and support-limit documentation. |
| `docs/superpowers/plans/2026-10-17-recon-r5.md` | Completed scoped implementation checklist and review focus. |
| `docs/recon_r5_validation.md` | This report. |

The existing R3 parser and R2 inventory were reused without changes. Business logic remains in `core/recon`; UI glue remains in the existing Recon panel.

## Exact adapter behavior

The sole profile is **Local Self-Test**. The supervisor executes an absolute verified executable directly, without a shell, using exactly:

```text
-sT -Pn -n -p 80,443,8080,8443 --max-retries 1 --max-rate 10 --host-timeout 30s --no-stylesheet -oX - 127.0.0.1
```

This is TCP connect on four fixed loopback ports, with no DNS or host discovery, one retry, requested maximum rate 10, 30-second host timeout and 40-second overall supervisor timeout. Verification uses only `--version` with a five-second timeout. There are no configurable flags, external targets, NSE scripts, UDP, OS detection or service version probes. Other tools remain detection-only.

The shared supervisor retains at most 1 MiB combined stdout/stderr per run; truncation prevents import. The unchanged R3 import limit remains 8 MiB. Native pipe reads and GUI work are bounded, and raw XML is never saved permanently.

## Windows process safety results

Twenty Windows integration cases cover native APIs, image locks and harmless local Python processes; nineteen existing supervisor tests use controlled QProcess doubles. The combined focused suite passed: **39 passed in 4.09s**, exit code 0.

Verified native behavior includes startup, successful completion, nonzero exit, startup failure, assignment failure before any fixture marker executes, cancellation during STARTING and RUNNING, timeout, shutdown, and application `aboutToQuit`. Real parent and child handles were checked for membership in the exact same job and observed terminated after stop. Normal parent exit cleans up a surviving child; forced TerminateJobObject failure falls back to kill-on-close. Flooded output remains bounded, and argument quoting preserves inert fixture data.

Launch uses CREATE_SUSPENDED, assignment to a non-inheritable kill-on-close Job Object, then ResumeThread. No child code runs before containment. Terminal reporting waits for retained process handles as well as job accounting, because Windows can report zero active job members just before process handles signal exit.

Independent review found and verified a correction for an executable replacement race. Static approval holds a read handle denying write/delete across discovery, resource/signature checks and digest reads. Native start holds the same kind of lock after STARTING observers, revalidates the capability under the lock, and creates the suspended image before releasing it. Real tests cover denied write/replacement, an existing writer, revoked preflight and lock release after failure. Follow-up review found the issue closed; its native/adapter suite passed **83 tests**, exit code 0.

## Tool validation and local authorization

Discovery is passive and never approves an executable. The explicit file chooser approves an absolute local `nmap.exe` for static PE/resource identity and cached Windows Authenticode verification. Recognized publishers are `Nmap Software LLC` and `Insecure.Com LLC`. Network/reparse/script candidates, unsigned or mismatched images, and unavailable cached trust fail closed before probing. SHA-256 binding is rechecked when queued execution reaches the front and under the final native image lock.

Only a successful, complete contained version response matching signed file resources enables the scan action. Each click requires a fresh confirmation describing the exact target, ports, TCP connect technique and local connection effect. The opaque one-use local approval belongs to the exact Nmap adapter/profile. R1 targets remain unreviewed; domain ScopeApproval behavior and external/IP-range restrictions remain unchanged.

## XML and inventory handling

Only trusted local process output can normalize the exact ASCII declaration `<!DOCTYPE nmaprun>`. Original XML is first checked for well-formedness and structural limits with declaration-aware Expat handlers, then the sole harmless declaration is removed before the unchanged R3 parser runs. All external identifiers, internal subsets, entity declarations, unexpected/duplicate/misplaced DOCTYPEs, malformed or truncated XML and declaration-like comment/CDATA content are rejected. Stylesheets and schemas are never fetched. Offline XML import continues rejecting all DOCTYPEs.

Successful live XML must account for all four fixed ports and exactly one completed, up IPv4 loopback host, with successful run statistics and the TCP connect scan profile. Host timeouts and partial port outcomes are rejected. The original XML digest defines deterministic run identity; evidence retains its original byte size/hash, normalization flag, profile, target, ports and technique.

Only fully validated results enter `AssetInventory.import_batch`, using source `nmap`, label `Nmap Local Self-Test`, and format `Nmap live XML`. Existing observations remain intact. The current All Assets view and corresponding Run / Import History entry refresh through existing models. Identical output deduplicates. Failed execution or validation imports nothing, and zero open ports is a valid successful result.

## Actual Nmap execution

The user explicitly approved `C:\Program Files (x86)\Nmap\nmap.exe` and **one** localhost self-test. Both static verification and an actual contained `--version` process succeeded: **Nmap 7.992**, publisher **Nmap Software LLC**.

- Executable SHA-256: `338154325ed737b8739bf9bcbd7b78ca04b56282a48d171538099f33a4f940bd`.
- Actual fixed-profile scan: **SUCCEEDED**, exit code **0**.
- XML: **1,866 bytes**, complete/untruncated, containing the exact harmless DOCTYPE.
- Open ports: **0**; one loopback IP observation imported successfully.
- Existing fixture observations were preserved; history contains the pre-existing import and the live Nmap run.
- Live run ID: `nmap:sha256:14db86b0a514f8595c51eefa5f5c999408b0dbd717792a6077f602d70f01467e`.

No external scan or additional Nmap scan ran. This actual scan preceded final image-lock and partial-report hardening; those final changes were verified with harmless native fixtures and offline XML regressions, without consuming another scan confirmation. Locked static approval of the installed Nmap binary was checked again successfully afterward. No raw XML was retained on disk.

## Final full pytest output

Command from the repository root, using the existing venv:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
.\venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
```

```text
........................................................................ [  9%]
........................................................................ [ 19%]
........................................................................ [ 29%]
........................................................................ [ 39%]
........................................................................ [ 49%]
........................................................................ [ 59%]
........................................................................ [ 69%]
........................................................................ [ 79%]
........................................................................ [ 89%]
........................................................................ [ 99%]
.......                                                                  [100%]
727 passed in 22.09s
```

**Exit code: 0.** All 609 baseline tests and 118 added cases passed. Tests never launch Nmap; only explicitly marked harmless local Windows process fixtures may launch natively. Tests remain usable without Nmap installed.

`git diff --check` passed with exit code 0. Git emitted only its normal LF-to-CRLF conversion notices, with no whitespace errors.

## Windows GUI smoke test

A controlled startup used Qt's native **windows** platform, isolated settings, and the actual MainWindow. It opened and closed cleanly, verified initially disabled live actions, imported offline fixture assets/history, switched to the responsive Scraper tab and shut down with zero workers left. Captures of both Recon screens were inspected. No scan ran during GUI startup or this smoke test.

Manual smoke steps, at most five:

1. Start `main.py` using the existing venv; open Recon and confirm existing targets/assets remain usable and Local Self-Test starts disabled.
2. In Tool Manager choose the official local `nmap.exe`; check validated path, version and ready status after verification.
3. Click Local Self-Test and verify the confirmation lists only 127.0.0.1, the four ports and TCP connect; decline once to check no run starts.
4. With a fresh explicit confirmation, run once; check the terminal open-port count, All Assets, source `nmap` and the corresponding Run / Import History entry.
5. On a separately confirmed run, use Stop or close the application; confirm cleanup and absence of partially imported results.

Steps 4–5 require their own user confirmations; this report does not authorize extra executions.

## Known limitations and assumptions

- Live execution is Windows-only; other platforms retain the shared QProcess model but fail the live scanner safety gate.
- Official signed Windows builds and locally available cached certificate trust are required. Custom/unsigned builds or unfamiliar publishers require future reviewed support; online revocation checks are not performed.
- Tool approval, execution state and Recon inventory remain in memory. Session persistence is outside R5.
- The supported XML shape is intentionally restricted to this four-port self-test. Unusual or incomplete reports fail closed instead of being imported.
- Job Objects contain process lifetime; this is not a sandbox against malicious Python already running in the application or a compromised installed tool dependency.
- Approving the file chooser is treated as explicit path approval; every live scan still requires its separate confirmation.

## Git diff summary

Six tracked files changed, with **197 insertions and 39 deletions**, plus eleven new files listed above. Standard `git diff --stat` excludes these untracked new files:

```text
 core/recon/execution_policy.py     |  55 ++++++++++++------
 core/recon/process_supervisor.py   |  33 +++++++----
 tests/conftest.py                  |  23 +++++++-
 tests/ui/panels/test_recon_tab.py  |   5 +-
 tests/ui/test_recon_integration.py |   9 ++-
 ui/panels/recon_tab.py             | 111 +++++++++++++++++++++++++++++++++++--
 6 files changed, 197 insertions(+), 39 deletions(-)
```

The branch and HEAD are unchanged. Work is intentionally uncommitted and unpushed.
