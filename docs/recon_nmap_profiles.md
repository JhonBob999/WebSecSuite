# Nmap scan profiles (R7B-1)

The Nmap Tool Inspector's **Manage Scan Profiles…** action opens an offline
configuration dialog. Selecting, duplicating, editing or saving a profile never
resolves a target, starts a process, grants scope or changes a live scan.

The existing Local Self-Test and R5B Quick Network Discovery actions remain
separate. Their executable verification, one-shot approval, exact ports and
arguments, DNS preflight, Windows containment, cancellation and XML import rules
are unchanged. **Run Selected Profile…** uses the existing runtime and process
supervisor for the separate, strictly bounded R7B-1 execution policy.

## Built-in presets

All presets use TCP connect, maximum rate 10 and one retry. Built-in definitions
are immutable; duplicate one to create an editable custom profile.

| Name / stable ID | TCP ports | Host / overall timeout | Version probes |
| --- | --- | --- | --- |
| Quick Network Discovery / `quick-network-discovery` | 80,443,8080,8443 | 30 / 40 s | Disabled |
| Web Services / `web-services` | 80,443,8000,8080,8081,8443,8888,9443 | 45 / 60 s | Disabled |
| Standard TCP / `standard-tcp` | 1-1000 | 300 / 360 s | Disabled |
| Deep Service Review / `deep-service-review` | 1-1024 | 600 / 660 s | Enabled |

Quick matches the existing R5B settings and runs through **Public Scan**. Web
Services and eligible saved Custom profiles run through **Run Selected Profile…**.
Standard TCP and Deep Service Review remain editable through duplicates and
available in the selector, with a clear **Not executable in R7B-1** explanation.
No timing setting promises a complete scan before timeout.

Service detection sends additional probes. Nmap `--max-rate` does not constrain
every possible service-version probe. Version detection remains configurable and
saveable, but is not executable in R7B-1.

## Execution eligibility and confirmation

Configuration validation below intentionally remains broader than live execution.
The separate R7B-1 gate permits only the unchanged built-in Web Services profile
and saved Custom profiles satisfying every limit:

- TCP connect (`-sT`), 1–16 distinct TCP ports from 1 to 65535.
- Version detection disabled; maximum rate 1–10 probes/s; retries 0–1.
- Host timeout 5–60 seconds; overall timeout 10–90 seconds, greater than host timeout.
- Exactly one checked Target Manager hostname: `ginandjuice.shop`.
- Explicit fresh DNS preflight, one explicitly selected globally routable IPv4,
  and scope authorization for that exact IP on each attempt.

The inspector displays name, description, port count and canonical ports,
technique, rate, retries, timeouts, version detection, derived network impact and
execution eligibility. Ineligible profiles remain saved and editable. Selecting
or saving never starts DNS or a scan.

A default-No confirmation shows the exact hostname, numeric IP, profile and scan
settings, network impact and explicit IP authorization. Changing target, IP,
profile or DNS observation while the dialog is open invalidates it, including a
selection changed and then restored. A custom profile is checked against its
persisted record before and after the dialog, and again immediately before launch.
Declining, a changed selection or any rejected attempt clears the scope checkbox.

Trusted execution binds a fresh immutable validated profile, numeric address,
hostname, fresh DNS observation, executable identity/SHA-256 and exact typed argv
to a short-lived, one-shot approval. Saved custom document changes invalidate the
bound approval. The runtime revalidates before launch. Authorization tokens are
never saved, and DNS never grants permission.

Executable arguments are constructed directly from validated values:

```text
-sT -Pn -n -p <canonical-ports> --max-retries <0-or-1> --max-rate <1-to-10> --host-timeout <5-to-60>s --no-stylesheet -oX - <approved-ipv4>
```

These are passed as separate sequence elements. Overall timeout is enforced by
the process supervisor. No preview string, shell, arbitrary flags, NSE, UDP, SYN,
OS detection or service-version probing is executed. Existing executable locking,
signature checks and Windows Job Object containment remain required. Only one
Nmap operation can run; Stop, timeouts, output limits and shutdown cleanup apply.

## Results and evidence

The profile-specific bounded XML validator requires a successful complete Nmap
run, one approved numeric IPv4, TCP connect scan information and the exact
requested canonical port set. Individual ports and extraports must account for
every requested port without duplicate or unexpected identities. Open, closed and
filtered states are retained; zero open ports remains valid. Unexpected hostnames,
addresses, protocols, partial host-timeout reports, DTD/entity attacks and malformed,
truncated or oversized output are rejected without permissive fallback parsing.

Successful results reuse the atomic Asset Inventory import, preserving existing
assets, Nmap/Subfinder observations, correlation and Run / Import History. Evidence
includes approved hostname, scanned IP, profile ID/name, canonical ports, effective
arguments, rate/retry/timeouts, Nmap version, distinct run identity, XML SHA-256 and
DNS provenance. Failed, cancelled, timed-out or invalid runs add no partial history
or inventory records.

## Validation and preview

- Ports: ASCII numeric ports or explicit numeric ranges, comma separated,
  from 1 to 65535; at most 1024 distinct ports and 8192 input characters.
  Normalize duplicates and sort deterministically; format consecutive ports
  as compact ranges.
- Technique: `tcp-connect` only. No free-form flags, targets, NSE scripts, SYN,
  UDP, OS detection or executable arguments.
- Maximum rate: integer 1–100; retries: integer 0–3.
- Host timeout: integer 5–600 seconds; overall timeout: integer 10–900 seconds,
  strictly greater than host timeout. Booleans and numeric strings are rejected
  for integer fields.
- IDs: lowercase ASCII letter followed by lowercase letters, digits or hyphens,
  maximum 64 characters. Built-in IDs cannot identify a custom profile.
- Names: trimmed, nonempty, maximum 80 characters; description and network impact
  are limited to 2000 characters. Invalid text controls are rejected.
- Unknown or missing configuration fields are rejected.

The deterministic preview uses only allowlisted flags and the literal
`<approved-ip>` placeholder. DNS and host discovery are disabled; XML goes to
stdout without a stylesheet. Overall timeout is application metadata, not a new
CLI argument. The preview is illustrative text, never authorization or a trusted
execution specification.

## Custom storage

Location: Qt's per-user `GenericConfigLocation`, followed by
`WebSecSuite/nmap_profiles.json`. On Windows this normally resolves to
`%LOCALAPPDATA%\WebSecSuite\nmap_profiles.json`. Loading does not create it.

```json
{
  "schema": "websecsuite.nmap.profiles",
  "version": 1,
  "profiles": []
}
```

Each custom entry contains exactly `profile_id`, `name`, `description`,
`is_builtin` (false), `ports` (canonical string), `technique`, `max_rate`,
`max_retries`, `host_timeout_seconds`, `execution_timeout_seconds`,
`version_detection` and `network_impact`. Generated custom IDs survive renames
and reloads. Built-in definitions are never loaded from this file.

Limits: 64 custom profiles and 256 KiB per document. The complete document must
validate, including unique JSON keys and profile IDs, before any entry is loaded.
There are no fields for targets, credentials, executable paths or scope grants.
Scraper sessions and Recon observation schemas are unchanged.

Saving takes a per-file lock and reuses the existing JSON writer's same-directory temporary file, flush,
fsync, close and atomic replacement. In-memory changes follow successful writes.
Corrupt, unreadable and unsupported files keep all built-ins available and block
custom writes; preserve the original file for manual recovery. External changes
require reopening the application before saving. No automatic repair or migration
is attempted.

## Offline verification

Use the existing venv and run the complete suite, including the harmless local
native-process Windows fixtures:

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
.\venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
git diff --check
```

Clear any inherited `PYTEST_ADDOPTS` marker exclusion before running. The 24
previously deselected native-process tests have also passed on Windows using
harmless local fixtures; no public Nmap scan is part of automated verification.
The actual MainWindow startup/editing test records forbidden network, process,
thread and job-submission attempts and requires zero attempts. Offscreen layout
checks cover 920×740 and 700×480. Real scans are never part of profile tests.

## Windows GUI acceptance checks

1. Inspect all selector summaries, hide/show Tool Inspector, switch tools and
   resize the dark-theme inspector and profile manager. Existing controls remain reachable.
2. Save/reload a bounded Custom profile; verify selector refresh, rename/delete
   and unsaved-edit handling. Check that 17 ports, high rates and `-sV` stay saved
   but disabled; Standard TCP and Deep Service Review must remain disabled.
3. Preflight only the checked `ginandjuice.shop`, explicitly choose one authorized
   IPv4 and inspect Web Services confirmation. Decline, change the IP/profile and
   verify scope resets and a new confirmation is required.
4. With independently confirmed IP authorization, manually run the first Web
   Services and bounded Custom scans. Inspect provenance and zero-open results;
   exercise Stop and confirm cancelled runs add no inventory/history records.
5. Recheck Local Self-Test and the original Quick Public Scan, plus existing
   Nmap/Subfinder imports and history. No real public scan runs automatically.

Stop after R7B-1. Standard TCP, Deep Service Review, version detection and all
R7B-2 work remain excluded until manual acceptance. No commit or push is part of
this stage.
