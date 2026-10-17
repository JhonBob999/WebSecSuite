# R6 — Safe Live Subfinder Integration

## Scope and preflight

Implemented the requested Target Manager → Subfinder → shared ProcessSupervisor
→ JSONL adapter → Asset Inventory → Run / Import History flow. Work started in
a clean `bugfix/dec-20-pack` checkout at
`6e7f3534393588ffb6fd0a16b201e5ceb7492051`. That commit contains R5B. Branch and
HEAD remain unchanged. No commits, pushes, installation, updates, live
enumeration, target DNS lookups or public target traffic were performed.

## Files changed and purpose

| File | Purpose |
| --- | --- |
| `core/recon/subfinder_adapter.py` | Pinned release identity, local executable approval, isolated configuration, bounded version verification and one-shot exact-domain capabilities. |
| `core/recon/subfinder_output.py` | Strict complete-process JSONL parsing, hostname normalization/deduplication and bounded provider/run evidence. |
| `core/recon/subfinder_runtime.py` | Connects setup, approval, supervisor lifecycle and atomic inventory/history import. |
| `core/recon/execution_policy.py` | Narrow Subfinder capability dispatch; optional immutable child environment and working directory. |
| `core/recon/process_supervisor.py` | Passes explicit child environment/directory to the existing process backend. |
| `core/recon/windows_process.py` | Supports an explicit Unicode environment and directory while retaining suspended creation, image locking and Job Object containment. |
| `ui/recon_subfinder.py` | Shared-inspector Subfinder controls, explicit setup/run confirmation, exclusions, modal invalidation, Stop and history handoff. |
| `ui/panels/recon_tab.py` | Runtime construction, inspector visibility, inventory refresh and shutdown wiring. |
| `ui/recon_tool_info.py` | Updates Subfinder capabilities, trust requirements, fixed profile and third-party impact. |
| `tests/core/recon/test_subfinder_adapter.py` | Release identity, mutation, version, exact CLI, scope, expiry/reuse and configuration isolation tests. |
| `tests/core/recon/test_subfinder_output.py` | Synthetic JSONL validation, provider merging, bounds, empty results, history/correlation and atomic rejection tests. |
| `tests/core/recon/test_subfinder_runtime.py` | Completion/failure gates, cancellation, shutdown, reentrancy, status sanitization and real inventory integration. |
| `tests/core/recon/test_subfinder_process.py` | Fixed-profile real-supervisor tests with injected processes, queue revalidation and a complete offline setup-to-import flow. |
| `tests/core/recon/test_subfinder_windows.py` | Real harmless Windows child environment/directory and parent/child cancellation, timeout and shutdown tests. |
| `tests/core/recon/test_process_supervisor.py` | Extends the existing process double to record explicit environment/directory. |
| `tests/fixtures/recon_process.py` | Adds a harmless local environment/directory reporting mode. |
| `tests/ui/panels/test_recon_subfinder.py` | Inspector controls, scope/setup modal changes, checked targets, exclusions, visibility and inventory handoff. |
| `tests/ui/test_subfinder_startup.py` | Guarded offscreen real MainWindow startup with zero network/process/worker attempts. |
| `tests/ui/panels/test_recon_nmap_live.py` | Updates the exact global button expectation for new Subfinder controls. |
| `tests/ui/panels/test_recon_tab.py` | Updates Subfinder capabilities and keeps httpx/FFUF detection-only expectations. |
| `tests/ui/test_recon_integration.py` | Updates the integrated window's exact Recon button expectation. |
| `docs/superpowers/plans/2026-10-17-recon-r6.md` | Scoped implementation and review checklist. |
| `docs/recon_r6_validation.md` | This validation report and manual handoff. |

Existing ToolDiscoveryService already safely detects Subfinder candidates and
is reused without changes. ObservationBatch, AssetInventory, Target Manager,
generated Qt files and Nmap adapters/profiles were not rewritten.

## Executable verification and trust

Only official **v2.17.0 Windows amd64 or arm64** builds are supported initially.
The user supplies an absolute local `subfinder.exe` and its official local ZIP,
then explicitly approves verification in a default-No dialog. Selection or a
matching filename never executes a candidate.

The pinned archive SHA-256 values are:

| Archive | SHA-256 |
| --- | --- |
| `subfinder_2.17.0_windows_amd64.zip` | `a3fd612928d591fb31c1e59a2e06055e364421ba32251e553073f5673a2d3103` |
| `subfinder_2.17.0_windows_arm64.zip` | `579f8dc7b5bb3da01672fb8b48ba1c232002fe20d1f22d3ddf4b952790f65fe9` |

These match both the official release checksum text and GitHub asset metadata.
The inspected release publishes SHA-256 checksums but no detached signature or
attestation asset. This is pinned artifact trust based on official HTTPS release
provenance, not a claim of Windows Authenticode publisher verification.

Local paths reject UNC/device/mapped-network paths, alternate streams,
reparse points, missing files and unsuitable native images. Executable and ZIP
reads are bounded at 128 MiB and protected by the existing Windows deny-write/
delete file lock during approval. The entire ZIP must match its pinned checksum;
exactly one bounded `subfinder.exe` member is read in memory without extraction,
and its SHA-256 must equal the chosen executable's SHA-256. Archive hashes are
never compared directly to executable hashes.

Only then can a five-second contained `-version -duc -nc` probe run. Its bounded
successful output must match `v2.17.0` and the optional exact private configuration
directory message. Bounded ANSI SGR logger prefixes are accepted because this
release handles `-version` before applying `-nc`. Unknown version messages fail.

The approved path, SHA-256 and version are held in immutable identity-registered
objects. Prepare, submit, queue launch and native launch revalidate trust; native
launch checks again under the existing image lock. Unsupported provenance,
changed files/configuration or unavailable containment keeps execution disabled
with a HOLD reason. Nmap's resource/publisher/Authenticode checks are unchanged.

## Exact executable profiles

Version verification only:

```text
-version -duc -nc
```

The sole discovery profile, **Passive Standard**:

```text
-d <normalized-selected-domain> -oJ -cs -silent -nc -duc -rl 2 -timeout 15 -max-time 2
```

Arguments are an immutable tuple in the trusted plan, converted to the existing
Qt argument list only at the process boundary. The profile has a **150,000 ms**
supervisor timeout, above the two-minute tool limit. The rate is a global maximum
of two external-source HTTP requests per second; the source timeout is 15 seconds.
It is not a target packet rate. There are no user flags, active/IP-resolution,
recursive/all/custom-source modes, proxy rotation, batch runs or automatic retry.

Subfinder and goflags load configuration before version/discovery handling.
Each approved candidate therefore owns a private temporary working directory,
private APPDATA/Subfinder configuration containing `{}`, and an empty provider
configuration. A minimal explicit environment supplies only necessary Windows
system paths and those private directories/configuration paths. Ambient API keys,
proxy variables, PATH and user configuration are not inherited. Configuration
is checked before each operation. There is no provider configuration editor.
This deliberately limits coverage to sources usable without supplied keys.
Other tools retain their existing environment and directory behavior.

## Scope and confirmation

Exactly one checked, valid Target Manager hostname is normalized using R1 rules;
there is no DNS or public-suffix lookup. The selected canonical hostname is the
query root; no example domain has a special authorization grant.

Every run has a default-No confirmation showing the exact root, Passive Standard
profile, limits and third-party request/logging impact. A fresh exact-domain
ScopeApproval is constructed only after confirmation; existing exclusions are
retained and checked by the shared scope policy. Selection, past Nmap approval,
discovery and stored positive UI grants grant no Subfinder permission.

The opaque operation grant binds the tool, root, profile and scope snapshot,
expires after 60 seconds and prepares one specification. Each specification
submits once. The plan is checked again at queue launch and native creation.
Target/setup/runtime/scope revisions invalidate nested modal changes, including
A → B → A changes. Selecting another executable or ZIP requires verification
again. No reusable approval is persisted or copied into Target Manager.

## JSONL, provenance and inventory

The parser supports the verified v2.17.0 passive `-oJ -cs` writer schema:
`host: string`, `input: string`, `sources: string[]`. Other shapes/fields, duplicate
JSON keys, malformed JSON, nonfinite values, invalid UTF-8, invalid hostnames,
missing final encoder newline and mismatched input roots fail the whole batch.
Limits are 1 MiB combined captured stdout/stderr, 16 KiB per line, 10,000 records
and 31 combined provider references per hostname. Failed/cancelled/timed-out or
truncated process results cannot reach import.

R1 normalization deduplicates hostnames; repeated records combine bounded,
sanitized provider references. Unrelated domains are excluded by label boundary.
The ObservationBatch contains only `source=subfinder`, `type=hostname` records.
It includes no IP/service observations, reachability, vulnerability or invented
confidence claims. Evidence retains the query root, normalized hostname, source
names, profile, passive mode, job/run identity, stdout hash/size and bounded
discovery counters. Raw configuration, credentials and rejected output are not
persisted or shown in diagnostics.

Only AssetInventory.import_batch performs the atomic mutation. Each successful
execution uses `subfinder:passive:<job-UUID>`, correlating repeated hostnames while
retaining separate observations/history. Empty successful output imports a
zero-observation history entry; its label retains profile and root. Existing
assets/Nmap observations, All Assets/per-import filters and Details are reused.
No discovered name is automatically added to Target Manager or authorized;
the existing manual handoff creates Unreviewed targets.

## Offline validation

Existing venv: Python **3.13.15**. All validation uses
`PYTHONDONTWRITEBYTECODE=1` and Qt offscreen mode.

An initial full-suite run passed **1,117 tests in 40.61s**, exit **0**. Subsequent
hardening added stricter version-type cases, isolated-environment native process
tree cases and the guarded actual MainWindow startup test.

Final required command:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
.\venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
```

Final result: **1,124 passed in 45.74s**, exit **0** — **223 additional cases**
over the accepted 901-test baseline. This includes the existing R1–R5B,
UX-01/UX-02 and Scraper regressions. All new tests use synthetic JSONL,
injected processes or the explicitly allowed harmless local Windows fixture.

`git diff --check`: exit **0**, no whitespace errors. A separate check of all
new files also passed. Existing LF/CRLF notices and the inaccessible ignored
`.pytest_cache` directory warning do not affect the result; cache use was disabled.

Native tests run only the harmless local Python fixture. They check exact Job
Object membership and signaled process handles: cancellation, timeout and
shutdown leave neither parent nor child alive, including with the explicit child
environment. Existing tests also cover application quit, kill-on-close fallback,
normal-parent-exit cleanup, failed containment before resume, bounded flood
capture, argument quoting and image write/replace protection. There are **24**
native Windows backend cases across the existing and new native test modules.
No real Subfinder process or provider request was run.

Guarded real MainWindow startup opens Recon/Subfinder, checks one synthetic
`example.test` target, confirms live actions stay disabled, toggles Hide/Show,
checks scroll layout, returns to Scraper and shuts down. It records **zero**
socket/DNS/process/URL/worker starts, zero remaining workers and no inventory
mutations. The captured startup image was visually inspected.

Independent implementation review found two runtime reentrancy/type issues,
which were reproduced and fixed with tests. Its fresh focused review verification
passed **218 tests**, exit **0**, with no remaining actionable findings.

## Git diff summary

The complete uncommitted change contains **23 files: 10 modified and 13 new**,
including implementation, tests and these two documentation artifacts. Standard
`git diff --stat` shows tracked modifications only; the file table above also
includes new files. No files were deleted or renamed. HEAD/branch are unchanged.
Work stops at R6; no R7, httpx execution, FFUF or JS/Frontend work was started.

## Limitations and manual Windows checks

- Trust is pinned to the two v2.17.0 Windows archives; other versions,
  architectures and locally built executables stay on HOLD pending review.
- Official release artifact trust depends on the reviewed HTTPS checksum pins;
  no detached binary signature or attestation was available for this release.
- Provider credentials/configuration/proxies are intentionally isolated;
  key-required sources are unavailable and empty output can reflect limited
  provider coverage. A successful exit cannot establish completeness of any
  third-party dataset.
- Actual official-binary version execution, live provider compatibility and
  real enumeration were not tested. Native lifecycle evidence uses harmless
  fixtures. Process lifetime containment does not sandbox hostile software.
- Root selection uses existing hostname normalization; it does not infer a
  registrable apex or legal ownership. Returned names remain unreviewed evidence.

At most five manual GUI smoke checks:

1. Select Subfinder, choose the supported official local executable/ZIP and
   explicitly approve verification. Check version/path/status and that simply
   choosing a file performs no execution. A mismatched ZIP or changed executable
   must keep Run disabled with a HOLD explanation.
2. Check one authorized domain; inspect the exact root/profile/provider impact
   confirmation. Decline, change the target, or select multiple names and verify
   no operation starts. A configured exclusion must override confirmation.
3. Only after separately authorizing live passive requests for the displayed
   root, confirm one run. Review hostname/source evidence, counts and a distinct
   Run / Import History entry; use All Assets and per-import filters. Check that
   a manual Target Manager handoff remains Unreviewed.
4. During another separately authorized run, press Stop or close the application;
   confirm no partial assets/history are imported. The next attempt must require
   a new confirmation.
5. Resize/Hide/Show the inspector, switch between tools/pages and return to
   Scraper. Confirm Nmap controls remain available as before and httpx/FFUF
   remain detection-only.

## Official references

- [Subfinder usage and flags](https://docs.projectdiscovery.io/opensource/subfinder/usage)
- [Official repository](https://github.com/projectdiscovery/subfinder)
- [v2.17.0 release](https://github.com/projectdiscovery/subfinder/releases/tag/v2.17.0)
- [Official checksum asset](https://github.com/projectdiscovery/subfinder/releases/download/v2.17.0/subfinder_2.17.0_checksums.txt)
- [Release API asset digests](https://api.github.com/repos/projectdiscovery/subfinder/releases/tags/v2.17.0)
- [Tagged flags/version/config handling](https://github.com/projectdiscovery/subfinder/blob/v2.17.0/pkg/runner/options.go)
- [Tagged passive JSONL writer](https://github.com/projectdiscovery/subfinder/blob/v2.17.0/pkg/runner/outputter.go)
- [Tagged passive output selection](https://github.com/projectdiscovery/subfinder/blob/v2.17.0/pkg/runner/enumerate.go)
- [Ambient API key handling](https://github.com/projectdiscovery/subfinder/blob/v2.17.0/pkg/runner/initialize.go)
- [Goflags default config parsing](https://github.com/projectdiscovery/goflags/blob/v0.2.1/goflags.go)
- [Goflags config path derivation](https://github.com/projectdiscovery/goflags/blob/v0.2.1/path.go)
- [Release checksum configuration](https://github.com/projectdiscovery/subfinder/blob/v2.17.0/.goreleaser.yml)
- [Release workflow](https://github.com/projectdiscovery/subfinder/blob/v2.17.0/.github/workflows/release.yml)
