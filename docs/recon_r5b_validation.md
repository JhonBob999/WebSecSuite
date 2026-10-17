# R5B — Authorized public Nmap target

## Scope and baseline

Implemented only the separately approved public profile for `ginandjuice.shop`.
The working branch is `bugfix/dec-20-pack`, baseline HEAD
`ce2c57e0fbd0dffcf78682ce333dd36b15e6a047`. Read-only preflight found no
uncommitted changes. Baseline validation: **746 passed in 25.41s**, exit **0**.
No commit, push, real public scan, or real target DNS lookup was performed.

## Files changed and purpose

| File | Purpose |
| --- | --- |
| `core/recon/public_target.py` | Separate asynchronous DNS preflight, exact target/public IPv4 gates, bounded observations, expiry and one-use consumption. |
| `core/recon/nmap_adapter.py` | Dedicated public trusted adapter and opaque per-run approval; retains executable verification, hashing and unchanged localhost profile/parser. |
| `core/recon/nmap_public_output.py` | Separate strict public XML validation and bounded timestamped DNS/run evidence. |
| `core/recon/nmap_runtime.py` | Integrates public preflight, one active operation, completion/cancellation/timeout gates and atomic inventory import. |
| `core/recon/execution_policy.py` | Updates module documentation for the additional narrow Nmap grant; policy behavior is unchanged. |
| `ui/recon_public_nmap.py` | Nmap-only controls, explicit IP/scope selection, confirmation and async/modal invalidation. |
| `ui/panels/recon_tab.py` | Connects public controls to the existing inspector and updates Nmap capability text. |
| `ui/recon_tool_info.py` | Updates only Nmap guidance, rate/timeouts, network impact and result meaning. |
| `tests/conftest.py` | Blocks Qt DNS lookup in addition to existing offline network/process guards. |
| `tests/core/recon/test_public_target.py` | Target selection, DNS failure/cancellation/expiry, global IPv4 filtering, issuance and scope tests. |
| `tests/core/recon/test_nmap_public_adapter.py` | Exact arguments, immutable bindings, approval expiry/reuse, image changes and localhost compatibility. |
| `tests/core/recon/test_nmap_public_process.py` | Real supervisor with fake processes: cancellation, timeout and queue-time expiry/image/containment checks. |
| `tests/core/recon/test_nmap_public_output.py` | Public/zero-open XML, state metadata, malformed/hostile XML, provenance and atomic inventory regression. |
| `tests/core/recon/test_nmap_public_runtime.py` | End-to-end controller gates, distinct runs, failure preservation and no retry. |
| `tests/ui/panels/test_recon_nmap_public.py` | Fourteen offline UI cases including modal changes, target invalidation and narrow inspector layout. |
| `tests/ui/panels/test_recon_nmap_live.py` | Extends inert runtime doubles and expected Nmap buttons; retains Local Self-Test checks. |
| `tests/ui/panels/test_recon_tool_inspector.py` | Extends inert runtime double; retains UX-02 visibility/layout checks. |
| `tests/ui/test_recon_integration.py` | Updates exact button expectation for the two public Nmap actions. |
| `docs/superpowers/plans/2026-10-17-recon-r5b.md` | Scoped implementation and review checklist. |
| `docs/recon_r5b_validation.md` | This validation report and manual handoff. |

No generated Qt files, asset database, general scope bypass, or other tool
runtime was added. `nmap_import.py`, `inventory.py`, `targets.py`,
`process_supervisor.py` and `windows_process.py` need no implementation changes.

## Exact preflight rules

1. Read checked Target Manager records, independently of highlighted rows.
   Exactly one selection is required. R1 hostname normalization must yield
   exactly `ginandjuice.shop`; URLs, IPs, subdomains and other names are rejected.
2. Only pressing **Public Target Preflight** starts an asynchronous Qt system
   DNS A query. Construction, selection, discovery, imports, Hide/Show and tool
   switches do not resolve or authorize anything.
3. A query has a 10-second application timeout. Accept at most 32 IPv4 answer
   records and 8 CNAME records, deduplicated after canonical validation. Reject
   the whole result if any IPv4 is invalid or nonglobal; private, loopback,
   link-local, multicast, reserved, unspecified, documentation and shared
   address space are excluded.
4. Display the canonical target, all accepted IPv4 addresses, available CNAME
   information, UTC observation time and resolver description. CNAME and
   multiple-address warnings are heuristic and explicitly incomplete and
   non-authoritative. DNS never proves permission or infrastructure ownership.
5. The address combo always starts with an unselected placeholder, including
   for a single answer. The user must select one address and explicitly check
   that the exact IP is within their authorized scope.
6. Preflight expires after 300 seconds. Checked-target changes, DNS restart,
   expiry, executable setup and shutdown invalidate displayed preflight.
   IP changes and every confirmation attempt reset the scope checkbox.
7. Public Scan additionally requires verified Nmap, Windows containment, no
   active operation and a fresh matching observation. A default-No modal
   confirmation shows exact hostname, IP, profile, ports and impact. Its nested
   event loop is followed by another target/IP/observation/freshness check.
8. Each submitted scan consumes its preflight; the next run requires a new
   preflight, selected address and confirmation. Nothing updates Target
   Manager's reusable scope status or persists an authorization grant.

## Exact public Nmap profile

**Quick Network Discovery**, with the approved numeric IPv4 substituted only
for `<approved-ipv4>`:

```text
-sT -Pn -n -p 80,443,8080,8443 --max-retries 1 --max-rate 10 --host-timeout 30s --no-stylesheet -oX - <approved-ipv4>
```

The process supervisor timeout is **40,000 ms**. There are no NSE, OS, UDP,
version-detection, arbitrary ports/flags, recursive discovery or automatic
scan retries. One Nmap operation runs at a time in the shared runtime. This
reports reachable TCP ports, not verified vulnerabilities. Local Self-Test
retains its exact original arguments and `127.0.0.1` validation.

## Approval and launch binding

Only service-issued, fingerprinted, unchanged DNS observations can issue a
public grant. The opaque frozen identity-registered grant binds the verified
tool object, canonical hostname, exact selected IP, profile, full arguments,
executable path, SHA-256 and expiry. Its lifetime is at most **60 seconds** and
cannot exceed DNS observation freshness. Each observation issues one grant;
each grant prepares one execution specification; each specification is
submitted once. Forged/copied/mismatched/reused/expired grants fail closed.

The execution policy revalidates on prepare, submit and queue launch. The
existing Windows backend revalidates again while holding its deny-write/delete
image lock before suspended creation, then assigns the process to the private
kill-on-close Job Object before resuming. Official PE identity, cached
Authenticode publisher trust, successful bounded version verification and
SHA-256 checks are preserved. DNS is not resolved again by Nmap (`-n`).

## XML and inventory rules

Runtime requires complete successful process exit, correct public adapter
identity and no stdout/stderr truncation, cancellation, timeout or stop request.
Public XML must be nonempty bounded bytes (R3's 8 MiB ceiling, additionally
bounded by the supervisor's combined 1 MiB capture), structurally bounded and
well formed. It must identify `scanner="nmap"`, one successful completion,
exactly one up/non-timed-out host and matching one-host run statistics.

Exactly one IPv4 address must equal the approved numeric target. Hostnames,
alternate addresses, host hints, scripts, OS/trace data and unsupported tree
elements are rejected. Exactly one connect/TCP scaninfo must declare the four
allowed ports. Explicit ports must be distinct and from that allowlist, with
one open/closed/filtered state each. Valid closed/filtered aggregate counts
must account for precisely the remaining ports; aggregate reason counts and
any reported port identities are checked for conflicts. Zero open ports is
successful. Closed/filtered outcomes remain in evidence, without inventing
open services.

The existing narrow normalization accepts only Nmap's exact inert
`<!DOCTYPE nmaprun>` in trusted output after validating the original document.
Other DTD/entity forms remain rejected; offline XML import remains unchanged.
The secure R3 parser and native observation validator are reused.

Atomic `AssetInventory.import_batch` adds source `nmap`, exact scanned-IP
observations and open services. Each public job has a distinct
`nmap:public:<job-id>` run identity, preserving the original XML SHA-256. The
profile, approved hostname and timestamped DNS observation are bounded inert
metadata with `ownership_verified=false`. No hostname ownership asset is
fabricated. Repeated scans merge asset identities while retaining distinct
observations/history. Failure preserves all prior assets, observations and
history. Existing All Assets, source/import filters, sorting and Details are
reused.

## Offline verification

Existing venv: Python **3.13.15**, PySide6 **6.9.1**.
All commands used `PYTHONDONTWRITEBYTECODE=1`.

```text
.\venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
```

Final result: **901 passed in 29.64s**, exit **0** (155 additional tests over
the accepted 746-test baseline). R1–R5, UX-01, UX-02 and Scraper regressions are
included. All new public tests use injected DNS, fake processes and synthetic
XML. No public scan or public target DNS resolution ran.

`git diff --check`: exit **0**, no whitespace errors. Git emits existing
Windows LF/CRLF conversion notices; no configuration was changed.

Guarded offscreen startup instantiated the real MainWindow with isolated
QSettings. It showed Recon, added and checked the supported target, verified
that selection performs no DNS and leaves public execution disabled, toggled
the inspector, returned to Scraper and shut down cleanly. **0 DNS/network/process
attempts; 0 workers left; exit 0**. The startup capture was visually inspected.
The suite also verifies the 206-pixel inspector with long CNAME text.

Independent whole-change review found no blocking issues. A minor observation
is retained: Stop cancels scan execution, while DNS preflight currently relies
on its 10-second timeout or target-change invalidation; its Stop button remains
disabled during DNS alone.

The complete working diff, including new files, contains **20 files**
(9 modified, 11 new). New files also passed a separate trailing-whitespace
check. Git HEAD and branch remain unchanged; all implementation is uncommitted.

## Known limitations and manual Windows checks

- IPv4 only and exactly one domain/profile/address per run; no automatic scope
  expansion or additional tool execution.
- CNAME visibility depends on what the system resolver includes in the A
  response; shared hosting/CDN warnings cannot establish ownership or permission.
- Authorization is the user's explicit statement; DNS and local checks cannot
  independently establish their legal scope. No grant is persisted for reuse.
- Signed executable trust uses the existing Windows cached certificate policy;
  unavailable trust/containment keeps execution blocked.
- TCP connect timing also depends on the operating system. Nmap's fixed retry
  and rate options are conservative controls, not a guarantee about every
  underlying OS retransmission. The supervisor enforces the overall timeout.
- No real public DNS answer or real public Nmap output was collected during
  implementation. The first public scan remains for manual Windows validation.

At most five manual checks:

1. Launch Windows GUI, verify official signed Nmap, run **Local Self-Test** and
   confirm its existing inventory/history behavior.
2. Check only `ginandjuice.shop`, start preflight and review IPv4/CNAME/warnings.
   Confirm no address is preselected and Public Scan remains disabled until an
   address and explicit IP-scope approval are supplied.
3. Change target/IP or decline confirmation; verify approval resets. Check that
   another hostname or multiple selected targets cannot start public preflight.
   Verify Hide/Show preserves inspector behavior and other tools remain detection-only.
4. Only with permission for the exact displayed IP, confirm one real public run.
   Inspect Nmap source, scanned-IP evidence, profile/hostname/DNS timestamp,
   distinct Run History and Details; reachable ports are not vulnerabilities.
5. Start another explicitly confirmed run and press Stop, or observe a timeout;
   confirm no partial import, existing inventory preservation and fresh preflight
   required before another attempt.

## Primary API references

- [Qt QDnsLookup API](https://doc.qt.io/qtforpython-6/PySide6/QtNetwork/QDnsLookup.html)
  for asynchronous A/CNAME records and abort behavior.
- [Nmap timing controls](https://nmap.org/book/man-performance.html) for the
  fixed maximum rate, retransmission and host-timeout semantics.
