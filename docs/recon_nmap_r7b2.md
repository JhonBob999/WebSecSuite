# R7B-2 Nmap integration

Implementation and automated validation are separate from manual Windows acceptance.
No commit, push, public scan, dependency installation, Npcap installation, service change,
firewall change or privilege elevation is part of this stage.

## Preflight and implementation design

The starting checkout was `bugfix/dec-20-pack`, HEAD
`ec68ca77ff6453211c9b2684885794c6c4637714`, with no tracked/untracked changes.
Git warned that its ignored `.pytest_cache` directory was unreadable. The baseline
virtual-environment suite passed 1,504 tests. Nmap exists at
`C:\Program Files (x86)\Nmap\nmap.exe`; installation presence grants no executable trust.

The existing signed-executable verification, image locking, one-shot execution
policy, Windows Job Object containment, supervisor, inventory transactions and
shared result viewers are reused. Local Self-Test, Public Quick Discovery and
the original narrow profile route keep their tested behavior. Extended options
are rejected by the narrow route and use the authorized-profile route instead.

The supplied implementation specification is the design brief. Work is divided
into coordinated changes to immutable configuration/persistence/editor; concrete
scope/capabilities/NSE/trusted execution; strict expanded XML/evidence; and the
shared runtime/inspector integration. Focused offline tests precede implementation,
followed by the full suite, native Windows process tests, visual Qt checks and
`git diff --check`. No separate execution runtime or generated Qt UI is introduced.

## Configuration and migration

Profiles remain immutable. Existing four built-ins, IDs, names and descriptions
are retained. Strict schema v1 documents load with defaulted extended settings;
loading does not rewrite the file. The next explicit save atomically writes v2.
Unknown fields, duplicate keys/IDs, invalid settings and unsupported versions reject
the complete document and block writes rather than repairing or overwriting it.
External file changes still require reopening. Configuration never stores scope,
executable approval or reusable authorization.

The existing manager groups ports/techniques, discovery/DNS, version/OS, NSE,
timing and routing/output. Built-ins remain read-only; duplicate them to edit.
Argument previews are inert and never executed.

## Capability matrix

| Capability | Configuration and behavior |
| --- | --- |
| TCP Connect | Explicit ports, common presets, all ports or top ports |
| SYN, ACK, Window, FIN, NULL, Xmas, Maimon | Typed options; Windows raw-packet checks required |
| UDP and TCP/UDP combinations | Separate port selections; raw-packet checks required |
| Service detection | `-sV`, intensity 0–9, all probes and version trace |
| OS detection | `-O`, limit/guess options; accuracy displayed as guesses |
| Discovery | `-sn`, `-Pn`, default probes, enumerated probe choices, `-sL` |
| DNS | No resolution or reverse DNS; names never expand execution scope |
| IPv4/IPv6 | Single family per run; exact literals, CIDRs, full IP ranges and hostnames |
| Timing | T0–T5, rate 1–100, minimum rate, retries 0–3, parallelism bounds |
| Timeouts | Host 5–600s, whole run 10–900s, NSE timeout 1–600s |
| Version budget | Optional stricter **whole-process** deadline for version-enabled scans |
| Traceroute | Explicit option and capability checks; observed hops are evidence |
| NSE | Verified-installation catalog, categories/filter/details, explicit named script selection |
| Output | Bounded XML to memory, strict validation and atomic inventory import |

Nmap has no independent `--version-timeout` option. A version execution budget
tightens the entire process deadline; it does not claim to time individual probes.
`--max-rate` does not reliably constrain version, NSE or discovery activity.
Long or large configurations can hit the deadline/output budget and then import
no successful observations. There are no hidden retries or silent technique fallbacks.
Service/NSE plans additionally constrain Nmap host groups to one host. Script-internal
task concurrency is script-specific; `--max-parallelism` is not a global NSE task limit.

## Scope, trust and NSE boundaries

Use the selected profile and Authorized Profile Scan section in Recon Tool
Inspector. Enter explicit targets or copy checked Target Manager entries, choose
the DNS family, then review concrete scope. Preflight uses asynchronous Qt DNS
with a deadline; it does not scan. Every CIDR address, including network/broadcast
boundaries, is shown and counted. Limit: 64 input identities and 256 concrete
addresses. Mixed families, unresolved/ambiguous or excessive scope are refused.
DNS is recorded as an observation and never grants IP ownership or authorization.

The user must authorize every displayed numeric address, inspect capabilities,
and confirm the final plan. Changed profile/scope/preview invalidates confirmation.
The adapter binds the one-shot grant to the exact scope, DNS snapshot, profile and
saved document digest, canonical arguments, signed executable identity/hash/version,
capabilities, installed data and selected script identities. Expiry, one-shot
preparation/submission and immediate launch revalidation remain enforced.

Npcap/driver/library and already elevated status are read-only observations.
Missing capabilities block execution with a reason. Nothing installs, elevates,
starts services or changes Windows/network security settings. Environment changes
between inspection and execution are checked again.

Raw-packet execution uses a conservative elevated-process gate even when Npcap's
AdminOnly setting permits non-admin capture. The capability report states this
integration limitation; it does not claim that Npcap universally requires elevation.

NSE catalog loading executes no Lua. Only explicitly selected installed scripts
reviewed for the finite target policy can run. The catalog explains unsupported
scripts. Broadcast, external/extra-target behavior, arbitrary Lua paths, category
expressions, `all`, automatic default scripts, file arguments, credential arguments,
command arguments and arbitrary raw CLI are unavailable. Selected intrusive
scripts require an extra confirmation; no preset activates them automatically.
Structured arguments use an audited allowlist and are redacted from execution
previews/evidence. Script/data files are revalidated before execution.

Nmap's `-sV` also activates its installed NSE `version` engine scripts internally.
The interface requires an additional explicit version-engine confirmation and
binds those implicit scripts and dependencies too; this behavior is not hidden
behind the service-version checkbox or enabled by saving a profile.
Results retain the approved explicit/implicit script IDs, categories and SHA-256
selection manifest even when individual scripts emit no output.

## Results and limitations

The expanded adapter retains the strict size/depth/element/entity/DTD checks,
scanner/version identity, successful complete statistics, exact target and
technique/protocol/port accounting. It captures host states, TCP/UDP service and
version/product/CPE evidence, non-open states, OS guesses and accuracy, traces,
NSE text/structure, timing, configuration and raw-output SHA-256. Reverse DNS and
traceroute observations never become newly authorized targets. Omitted down
hosts are labeled `not-reported` with aggregate accounting, not confirmed states.

Every explicit TCP/UDP port outcome is retained in compact state/protocol ranges,
including closed, filtered and unfiltered outcomes beyond the legacy 16-port
sample. Aggregate counts and only identities actually reported in their reasons
are retained. PTR names remain inert evidence even when they cannot be normalized
as target hostnames.

The shared evidence contract bounds metadata to 4KiB/reference and 32 references
per observation; NSE output is additionally bounded to 64KiB. Oversized, malformed,
partial, failed, cancelled, timed-out or inconsistent results reject the entire
import. The supervisor has a combined 1MiB output limit. Complete validated batches
use existing atomic Asset Inventory imports, Run / Import History and the shared
results/evidence viewer. Legacy XML validation is unchanged.
The XML gate retains its 8MiB import bound, depth32, 100,000 elements and 4,096
characters per XML name/attribute value. A single unusually long NSE output
attribute can therefore be rejected before the aggregate NSE limit is reached.

Unsupported CLI features include SCTP/IP-protocol/idle/bounce scans, source spoofing,
decoys, fragmentation, arbitrary payloads/interfaces/proxies, external script/data
paths, random targets, target files, arbitrary output files and raw expert CLI.
These are explicit integration limits, not claims of complete Nmap CLI parity.

## Manual Windows acceptance (five groups)

1. **Profiles:** Open the dark-theme app with existing custom profiles. Verify IDs,
   names and descriptions, duplicate a built-in, edit each settings tab, save/reopen,
   rename/delete/reset; confirm a corrupt-copy document is preserved and blocks writes.
2. **Capabilities:** Explicitly verify the installed official Nmap executable. Inspect
   capabilities without elevation/Npcap assumptions. Verify TCP Connect eligibility
   and clear blocking reasons for unavailable SYN/UDP/OS/traceroute options; no fallback.
3. **Authorization/lifecycle:** Use owned local targets (initially `127.0.0.1`), review
   exact numeric scope/count and final arguments. Decline confirmation once, run a
   harmless Connect profile, Stop an active run, exercise a short timeout and verify
   no partial import. Edit scope/profile during review and verify approval is invalid.
4. **Rich results:** Against an owned lab service only, enable version detection;
   where capabilities allow, try OS/UDP and a reviewed benign NSE script. Review
   service/CPE data, OS guess confidence and NSE evidence. High-impact scripts are
   optional and unnecessary for initial acceptance; never use an external public target.
5. **Regressions:** Inspect Asset Inventory, details/provenance and history. Exercise
   Local Self-Test and existing profile/editor/import/export/session/context-menu
   workflows. Check Subfinder UI remains unchanged; network regression scans require
   separate authorized manual scope, and are not run by automated tests.

Manual Windows acceptance remains a user gate before any commit or next task.

## References

Configuration and limitations were checked against the official
[Nmap option reference](https://nmap.org/book/man-briefoptions.html),
[NSE reference](https://nmap.org/book/man-nse.html),
[Windows installation notes](https://nmap.org/book/inst-windows.html) and
[scan technique documentation](https://nmap.org/book/man-port-scanning-techniques.html).
The installed `nse_main.lua` and HTTP library were inspected read-only to verify
implicit version-script selection and numeric-host redirect behavior.

## Final report — 2026-10-17

1. **Preflight:** Branch `bugfix/dec-20-pack`, HEAD
   `ec68ca77ff6453211c9b2684885794c6c4637714`; initially clean apart from Git's
   ignored-cache access warning. Baseline: 1,504 passing tests. Existing R7B-1,
   executable locking, approvals, strict XML, shared viewers and inventory
   transactions were inspected before product changes.
2. **Files added/modified:** 33 repository files: 17 production, 15 tests and this
   document. Exact file inventory and purposes follow below.
3. **Supported matrix:** See the capability matrix above. Connect, SYN, UDP,
   ACK, Window, FIN, NULL, Xmas and Maimon have typed construction and parser
   coverage; combinations, discovery/list modes, IPv6, service/OS/NSE, ports,
   timing, persistence and authorized execution are integrated into the GUI.
4. **Unsupported:** The listed CLI-specific features and unreviewed NSE scripts
   are explicitly unavailable. Mixed IP families require separate runs. Raw
   execution is conservatively held for unelevated processes, including Npcap
   installations permitting non-admin capture. No claim of full CLI parity.
5. **Migration:** Strict v1 load and v2 save round trips passed; stable IDs, names,
   descriptions and built-ins are preserved. Load never rewrites the original;
   corrupted documents block writes. No real user profile file was migrated
   during development.
6. **Windows/Npcap:** Read-only local observation: Windows, running Npcap,
   `AdminOnly=False`, IPv6 available, application unelevated. Raw execution is
   therefore held by this integration. Installation presence is not executable
   approval; the user must explicitly verify Nmap through the existing GUI.
7. **Scope/execution:** Complete bounded concrete scope, separate permission,
   expiring one-shot grants, saved-profile/executable/data/capability binding,
   launch revalidation, existing Job Object containment and shared supervisor.
   No automatic scope expansion, shell, elevation, retry or persistent token.
8. **XML/evidence:** Complete successful accounting precedes atomic import.
   Rich services/CPE, OS guesses, traces, scripts, all explicit port states,
   aggregates, inert PTR/DNS, configuration and original output SHA-256 are
   available through shared viewers. Legacy validators remain unchanged.
9. **Automated results:** Final complete suite:
   `venv\Scripts\python.exe -m pytest -q -p no:cacheprovider` — **1,700 passed in
   66.66 seconds**, no failures or skips. Native subset:
   `venv\Scripts\python.exe -m pytest -q -p no:cacheprovider -m native_local_process`
   — **24 passed in 7.62 seconds** (included in the full-suite coverage).
   Cache-provider exclusion avoids the pre-existing unreadable ignored cache;
   no tests or test directories were excluded from the complete run.
   `git -c core.autocrlf=false diff --check` — exit 0, no output.
10. **GUI validation:** Offline Qt startup, controls, confirmations, stale state,
    narrow layouts and existing workflow regressions passed. Dark Fusion GUI
    screenshots were rendered with local Segoe UI fonts and visually inspected;
    DNS/process launches were blocked during rendering. This is automated and
    visual QA, not manual desktop acceptance or live raw-scan verification.
11. **Manual acceptance:** Follow the five groups above. Initial acceptance uses
    owned local/lab targets and benign scripts; no public intrusive scripts are
    required. No Npcap installation or elevated privilege is assumed.
12. **Diff:** 14 modified files and 19 new files, all confined to Nmap integration,
    its tests and documentation. No generated Qt files, shared process backend,
    legacy XML adapter, Subfinder features or Scraper implementation changed.
    Branch and HEAD remain unchanged; no commit or push occurred.
13. **Remaining blockers:** Manual Windows acceptance remains pending. Live
    Connect/raw/OS/UDP/NSE scans were not run during implementation. Environment
    and documented output/script-policy limits remain visible; no automated
    test failures or unresolved independent-review findings remain. R7B-2 must
    not be declared acceptance-complete until the user performs the smoke plan.

### Production files

| Files | Status and reason |
| --- | --- |
| `core/recon/nmap_profiles.py`, `nmap_profile_store.py` | Modified: typed settings, command configuration, strict v1/v2 migration |
| `dialogs/nmap_profiles_dialog.py` | Modified: grouped advanced editor in the existing manager |
| `core/recon/nmap_profile_execution.py` | Modified: legacy route refuses extended options rather than ignoring them |
| `core/recon/nmap_adapter.py` | Modified: trusted authorized-profile route validation |
| `core/recon/nmap_runtime.py` | Modified: shared execution lifecycle, cleanup and result payload |
| `ui/panels/recon_tab.py`, `ui/recon_public_nmap.py`, `ui/recon_tool_info.py` | Modified: inspector integration and accurate guidance/summary |
| `core/recon/nmap_scope.py`, `nmap_scope_preflight.py` | Added: finite immutable scopes and asynchronous bounded Qt DNS |
| `core/recon/nmap_capabilities.py` | Added: read-only Windows/Npcap/raw/IPv6 checks |
| `core/recon/nmap_nse.py` | Added: installed catalog, structured argument and script risk policy |
| `core/recon/nmap_authorized_execution.py` | Added: canonical plans, ephemeral approvals and installed-data locking |
| `core/recon/nmap_authorized_output.py` | Added: strict rich XML validation and evidence |
| `ui/nmap_nse_catalog.py`, `ui/recon_authorized_nmap.py` | Added: catalog and explicit-scope controls using the shared inspector/runtime |

### Test files

Modified: `tests/core/recon/test_nmap_profile_store.py`,
`test_nmap_profiles.py`; `tests/ui/panels/test_nmap_profiles_dialog.py`,
`test_recon_nmap_live.py`; `tests/ui/test_recon_integration.py`.
Updates cover schema migration and the deliberate addition of controls; existing
security, layout and lifecycle assertions were retained.

Added under `tests/core/recon/`: `test_nmap_authorized_execution.py`,
`test_nmap_authorized_output.py`, `test_nmap_authorized_runtime.py`,
`test_nmap_capabilities.py`, `test_nmap_nse.py`, `test_nmap_profiles_v2.py`,
`test_nmap_scope.py`. Added under `tests/ui/panels/`:
`test_nmap_authorized_controls.py`, `test_nmap_authorized_ui_edges.py`,
`test_nmap_nse_catalog.py`.

All tests stay offline; native cases launch only the existing harmless local
Python fixture. No public network scans were run.
