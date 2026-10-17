# R5 Nmap Local Self-Test

The only live scanner profile targets `127.0.0.1` on TCP ports 80, 443,
8080 and 8443. Every execution requires a fresh confirmation. R1 domain
authorization and review state are unchanged; imported targets cannot reach
this execution path.

The adapter supplies this fixed argument list directly to the existing
supervisor, with no shell or externally supplied options:

```text
-sT -Pn -n -p 80,443,8080,8443 --max-retries 1 --max-rate 10 --host-timeout 30s --no-stylesheet -oX - 127.0.0.1
```

The supervisor's overall timeout is 40 seconds. The host timeout is 30
seconds and the requested maximum rate is 10 probes per second. The profile
does not use service version detection, scripts, UDP or OS detection.

## Executable approval and verification

Discovery remains read-only. A detected filename does not establish identity
and never starts a process. The user must approve an absolute local
`nmap.exe` file. Existing R4 discovery rejects network paths, reparse paths,
scripts and unsuitable native images.

Before any version probe, the adapter requires the official Windows Nmap
version-resource identity (`Nmap`, `Insecure.Org`, original file name
`nmap.exe`) and a successful native Windows Authenticode verification whose
verified signer organization is `Nmap Software LLC` or `Insecure.Com LLC`.
The [official Nmap resource source](https://svn.nmap.org/nmap/mswin32/nmap.rc)
defines these resource fields. The [official Nmap changelog](https://nmap.org/changelog.html)
documents its Windows signing history.

Signature verification uses `WinVerifyTrust`, with no UI and cache-only URL
retrieval. It does not perform online revocation checks. Missing cached
certificate trust, unsigned builds, custom builds and unfamiliar publishers
fail closed. No tool is downloaded or installed. See Microsoft's
[WINTRUST_DATA reference](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data).

A native deny-write/delete image handle remains open across resource,
signature and digest reads during approval, binding all checks to the same
file. A SHA-256 digest binds the approved file identity. The only permitted probe
is `--version`, with a five-second supervisor timeout. A complete successful
supervisor result must report the same Nmap version as its signed version
resources before the local scan becomes available. Every queued probe and
scan rechecks local discovery, the file digest and the process containment
gate. Confirmation objects and execution specifications are one-use and
accepted only by their exact reviewed Nmap adapters.

Live execution remains on HOLD unless the Windows process-safety gate is
available. Nmap verification and execution use the shared supervisor.

## XML and provenance

The offline R3 importer continues to reject every DTD and entity declaration.
Only the trusted live-output path accepts the exact ASCII declaration
`<!DOCTYPE nmaprun>`. A bounded, declaration-aware parser validates the
original document first; then the sole benign declaration is removed before
calling the unchanged R3 parser. External identifiers, internal subsets,
entity declarations, duplicate declarations and malformed XML are rejected.
Declaration-like text in comments or CDATA is rejected conservatively.
Stylesheet processing instructions are never followed.

A live report must describe exactly one completed, up IPv4 loopback host,
the fixed TCP connect scan, successful run statistics and outcomes accounting
for all four selected ports. Timed-out hosts, duplicate ports, unexpected
target identities and partial reports fail validation. Aggregate non-open
port results support scans with zero open ports.

The original XML byte digest defines the deterministic R3 run identity.
Evidence retains that digest and original size, indicates DOCTYPE
normalization and records the local profile, target, ports and technique.
The runtime imports the fully validated batch atomically into the existing
inventory. Raw XML is held only in bounded memory.

## Limits

R5 supports official signed Windows Nmap builds only. It does not persist
approval, add external/IP-range scope, or enable other scanner adapters.
Executable verification is an application boundary; it is not a sandbox
against malicious Python code running inside the application. Local changes
to installed tool dependencies require the same operating-system trust as
other installed programs.
