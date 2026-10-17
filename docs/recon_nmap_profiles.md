# Nmap scan profiles (R7A)

The Nmap Tool Inspector's **Manage Scan Profiles…** action opens an offline
configuration dialog. Selecting, duplicating, editing or saving a profile never
resolves a target, starts a process, grants scope or changes a live scan.

The existing Local Self-Test and R5B Quick Network Discovery actions remain
separate. Their executable verification, one-shot approval, exact ports and
arguments, DNS preflight, Windows containment, cancellation and XML import rules
are unchanged. The profile catalog is not registered with execution policy.

## Built-in presets

All presets use TCP connect, maximum rate 10 and one retry. Built-in definitions
are immutable; duplicate one to create an editable custom profile.

| Name / stable ID | TCP ports | Host / overall timeout | Version probes |
| --- | --- | --- | --- |
| Quick Network Discovery / `quick-network-discovery` | 80,443,8080,8443 | 30 / 40 s | Disabled |
| Web Services / `web-services` | 80,443,8000,8080,8081,8443,8888,9443 | 45 / 60 s | Disabled |
| Standard TCP / `standard-tcp` | 1-1000 | 300 / 360 s | Disabled |
| Deep Service Review / `deep-service-review` | 1-1024 | 600 / 660 s | Enabled |

Quick matches the existing R5B settings. The other timing values are conservative
configuration defaults chosen for R7A; they do not promise a complete scan before
timeout. Every profile in the manager is configuration-only, including copies
of Quick. Only the pre-existing runtime actions remain executable.

Service detection sends additional probes. Nmap `--max-rate` does not constrain
every possible service-version probe. Enabling it requires a separate execution
safety review in R7B, which is outside this change.

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

Use the existing venv and exclude the repository's native-process fixtures when
verifying without child process launches:

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:PYTEST_ADDOPTS = '-m "not native_local_process"'
.\venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
git diff --check
```

R7A verification: **1303 passed, 24 native-process tests deselected**, exit code 0.
The actual MainWindow startup/editing test records forbidden network, process,
thread and job-submission attempts and requires zero attempts. Offscreen layout
checks cover 920×740 and 700×480. Real scans are never part of profile tests.

## Windows GUI acceptance checks

1. Open Recon → Nmap → Manage Scan Profiles…; inspect each read-only built-in
   and resize the dialog in the dark theme.
2. Duplicate a preset, change its name/ports/timing, save, reopen the application
   and confirm the same custom profile loads.
3. Enter malformed ports and a timeout below the host timeout; confirm the inline
   error, cleared preview and disabled Save. Reset to the saved values.
4. Rename and delete a custom profile; test the unsaved-edit controls when changing
   selection or closing. Built-ins must remain intact.
5. Enable service detection on a duplicate and read the probe warning. Confirm
   profile edits leave scan controls idle and provide no Run action.

R7B must not begin until manual acceptance of R7A. No commit or push is part of
this stage.
