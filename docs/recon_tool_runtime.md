# Recon R4: shared tool runtime foundation

Tool Manager detects local candidates for Subfinder, ProjectDiscovery httpx,
Nmap and FFUF without executing them. **Refresh Detection** repeats this
read-only inspection. A candidate path does not verify compatibility, connect
an adapter, grant scope or permit execution. No scanner adapters, command
builders, installation or version probes are included in R4.

## Boundaries

- `core/recon/tool_discovery.py` returns immutable discovery records for future
  adapters. Missing, invalid, ambiguous and unverified candidates remain distinct.
  Python HTTPX launchers are not treated as ProjectDiscovery httpx. Executable
  suitability checks inspect bounded file content; they do not establish trust.
- `core/recon/execution_policy.py` keeps explicit `ScopeApproval` identities
  separate from R1 targets and R2/R3 observations. `preflight_scope` accepts exact
  domains or descendants of explicitly approved subdomain ranges. A range does
  not include its apex. Exact and range exclusions override grants. URLs, IPs,
  malformed hostnames and option-like targets are rejected without DNS lookup.
- `ExecutionPolicy.prepare` issues a sealed `ValidatedExecutionSpec` only through
  a private trusted adapter registry and that adapter's typed request. The
  registry is empty in R4, so imported dictionaries, selected targets and
  discovered paths cannot launch anything. The supervisor revalidates policy
  before queueing and starting. Python privacy is an application contract, not
  isolation from malicious code already running inside the application.
- `core/recon/process_supervisor.py` owns asynchronous QProcess lifecycle and
  bounded in-memory output. It uses an absolute program and an argument list,
  without shell invocation or ScraperTaskManager/global thread-pool changes.
  Structured output parsing and inventory ingestion remain future adapter work;
  the existing R3 Nmap XML importer is unchanged.

The lifecycle is `QUEUED`, `STARTING`, `RUNNING`, then exactly one of `SUCCEEDED`,
`FAILED`, `CANCELLED` or `TIMED_OUT`. Only one process can run at a time. Output
is drained in bounded chunks, shares a configurable retained-byte budget across
stdout and stderr, and reports truncation. Queue and completed-history limits
also bound retention. No raw output is automatically persisted, and diagnostics
do not echo arguments, environment contents or raw Qt error strings.

## Cancellation and Windows containment gate

Queued cancellation never starts a process. Explicit cancellation, timeout and
shutdown request graceful termination, then forceful termination after a bounded
grace interval. Process resources remain owned until the direct process stops;
repeated cancellation and late signals cannot complete a job twice. Application
exit requests immediate killing of the direct process without waiting in the GUI
thread. This fallback does not guarantee synchronous OS exit or delivery of
remaining Qt completion signals. Future owners must request shutdown before
quitting and retain the supervisor until `shutdown_finished`.

**This does not guarantee termination of descendants on Windows.** A Job Object
with kill-on-close containment needs race-free assignment before child code can
spawn descendants. Assigning a job only after QProcess emits `started` leaves a
race. The installed PySide6 QProcess binding does not expose Qt's Windows
`setCreateProcessArgumentsModifier`; implementing suspended native creation and
Job Object ownership would exceed this scoped patch. No Job Object framework is
added, and descendant cleanup has not been validated.

Reliable process-tree containment and its Windows tests are required before
connecting any live scanner adapter. Compatibility verification, reviewed
scanner-specific request/argument mapping and explicit authorization workflows
are additional future gates. R4 does not add a user execution path or change R1's
Unreviewed status.

## Offline verification

Use the project virtual environment with `PYTHONDONTWRITEBYTECODE=1`:

```powershell
.\venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
git diff --check
```

Lifecycle tests use controlled fake QProcess objects. Existing network and
process guards remain enabled. GUI integration tests initialize the main window,
refresh detection, process queued Qt events and switch between Scraper, Target
Manager and Asset Inventory while preserving imported data and results. Native
Windows appearance remains a manual check.
