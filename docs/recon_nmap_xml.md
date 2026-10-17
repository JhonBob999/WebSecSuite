# Recon R3: offline Nmap XML import

Asset Inventory → **Import Nmap XML…** reads an existing local `.xml` report into
the R2 inventory. It uses the native Windows file picker and the existing search,
type/source filters, sorting, selection and Universal Viewer. The source is
`nmap`. The status reports added and duplicate observations, new assets, and
existing assets receiving new observations (merged assets). An exact repeat
reports zero added observations, zero new assets and zero merged assets.

No Nmap installation, process execution, network lookup, scanner controls, target
scope expansion or session-format changes are involved. Imported targets retain
their Unreviewed scope status.

## Fields and correlation

- Requires an unnamespaced `nmaprun` root. An explicit `scanner` must equal
  `nmap`; absent scanner/version fields are left absent in evidence.
- Preserves scanner identity/version, run start/startstr, finished time/timestr
  and exit status when present, plus host start/end times.
- Normalizes explicit IPv4/IPv6 addresses and hostnames with the R2 rules.
  MAC addresses are ignored. Hostname assets sharing an IP stay separate.
  Hostnames must have at least two labels; invalid or single-label names reject
  the batch under the existing R2 contract.
- Preserves explicit host states (including up/down), defaulting missing or empty
  states to `unknown`. Hostnames and addresses co-reported by XML appear in host
  evidence; they are not new DNS-resolution claims or inventory relationships.
- Imports TCP/UDP services **only** for the exact port state `open`. Missing,
  closed, filtered, open|filtered and other states never create service assets.
  Bounded non-open samples and `extraports` summaries remain host evidence.
- A service uses the first explicit IP in XML order, otherwise the first
  explicit hostname. Additional addresses/names do not imply duplicate services
  on each name/address. A host without either produces no service assets.
- Service name is optional. Product, version, extrainfo, original confidence,
  identification method and tunnel are optional `nmap-service` evidence metadata.
  Integer confidence 0–10 maps to R2 confidence 0–1. Unusable/missing confidence
  stays absent; this measures service identification, not vulnerability confidence.
- R2 host/transport/port keys are unchanged; TCP/443 and UDP/443 stay distinct.

## Provenance and atomicity

The run ID is `nmap:sha256:<SHA-256 of original XML bytes>`. Source file digest and
byte size are retained in `nmap-run` evidence. References identify the content,
host ordinal, and port ordinal within the report. Filesystem paths and filenames
are not stored: unchanged copies or renamed files remain idempotent. Different
bytes (including timestamps, whitespace or encoding changes) form different runs
whose observations enrich the existing assets with separate provenance. Reports
with identical bytes cannot be distinguished as separate scans.

All generated records pass the existing native v1 observation validator. The
existing inventory transaction then checks stored conflicts and builds the next
snapshot before changing state. Any read, XML, limit, normalization or identity
failure leaves assets and observations unchanged. GUI failures also preserve
filters, sorting and selected details. Successful imports follow R2 selection
behavior and clear asset selection. JSON imports remain available and unchanged.

## Input safety and limits

The standard-library Expat parser rejects every DOCTYPE/DTD and entity declaration
before expansion, including declarations in UTF-16 input. External entities,
schemas and stylesheets are never fetched. Processing instructions, comments,
element text, scanner arguments, NSE script output and unsupported sections are
discarded. None becomes a command or validated vulnerability.

**Reports containing even a bare `<!DOCTYPE nmaprun>` are rejected.** This is
intentional under the R3 requirement to reject DTDs; use a trusted copy without
the declaration. The importer supports the report fields above rather than
performing DTD/schema validation. Non-Nmap scanner identities, malformed/truncated
XML and invalid core identity fields reject the complete import.

| Bound | Maximum |
| --- | --- |
| Local file read / XML input | 8 MiB, read at most limit plus one byte |
| Native normalized JSON envelope | Existing R2 8 MiB limit |
| Observations per import | 10,000 |
| Hosts / port elements | 10,000 / 50,000 |
| XML elements / depth | 100,000 / 32 |
| Attributes per element | 32 |
| XML element/attribute name or attribute value | 4096 characters |
| Retained optional text / exact state label | 128 characters |
| Host address/name samples in each evidence object | 4 each, plus omission counts |
| Non-open port / extraports samples | Up to 16 each, plus omission counts |
| Evidence metadata object | Existing R2 4096 UTF-8 bytes |

Long optional descriptions are shortened with a visible ellipsis. Identity values
are validated rather than shortened. Long state labels reject the report instead
of changing state meaning. Evidence samples shrink further if needed to meet the
metadata byte limit. Raw element text is not retained. Native XML encodings
supported by the installed Expat are accepted; unsupported encodings report an
import error. URL, UNC, device, alternate-stream and non-XML paths are rejected
before opening files.

## API and fixtures

```python
from core.recon.inventory import AssetInventory
from core.recon.nmap_import import parse_nmap_xml, read_nmap_file

inventory = AssetInventory()
result = inventory.import_nmap_file("tests/fixtures/nmap/recon.xml")
# Or inventory.import_nmap_xml(xml_bytes_or_text).
```

Synthetic fixtures are in `tests/fixtures/nmap/`: `recon.xml` covers documentation
IPv4/IPv6 addresses, multiple hostnames, TCP/UDP, open and non-open states,
optional fields, ignored NSE content, and an inert external stylesheet reference.
Other files cover truncation, wrong root and entity attacks. Tests generate
oversized, repeated, conflicting and high-record-count input locally without
committing large files.

Parser references: [Python Expat documentation](https://docs.python.org/3.13/library/pyexpat.html)
and [Nmap XML output reference](https://nmap.org/book/output-formats-xml-output.html).
