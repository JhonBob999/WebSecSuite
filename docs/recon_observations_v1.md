# Recon observations, native format version 1

Recon accepts a local UTF-8 `.json` file with this exact envelope. A UTF-8 BOM is allowed. The format contains imported observations; importing does not run a scanner, resolve DNS, fetch URLs, follow evidence references, execute commands, or expand a target scope.

```json
{
  "schema": "websecsuite.recon.observations",
  "version": 1,
  "run_id": "synthetic-run-1",
  "observations": [
    {
      "id": "hostname-1",
      "type": "hostname",
      "source": "synthetic-import",
      "value": "EXAMPLE.COM.",
      "confidence": 0.8,
      "evidence": [
        {"ref": "fixture:hostname-1", "kind": "synthetic", "metadata": {"line": 1}}
      ]
    },
    {
      "id": "ip-1",
      "type": "ip",
      "source": "synthetic-import",
      "value": "2001:0DB8::10"
    },
    {
      "id": "service-1",
      "type": "service",
      "source": "synthetic-services",
      "host": "example.com",
      "transport": "tcp",
      "port": 443,
      "service_name": "https"
    }
  ]
}
```

The four envelope fields are required. `schema` must match exactly and `version` must be integer `1`. `observations` must be an array; an empty array is a valid no-op. This importer does not accept generic scanner exports, JSON Lines, or other schema versions. Convert external data explicitly to this format first.

## Record fields

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | All records | Source record identifier, nonempty text |
| `source` | All records | Source label, nonempty text |
| `type` | All records | Exactly `hostname`, `ip`, or `service` |
| `value` | Hostname and IP | Hostname or unscoped IP literal |
| `host` | Service | Hostname or unscoped IP literal |
| `transport` | Service | `tcp`, `udp`, or `sctp`; input is trimmed and lowercased |
| `port` | Service | Integer from 1 through 65535; strings, floats, and booleans are rejected |
| `service_name` | Optional, service only | Nonempty descriptive name; not part of service identity |
| `confidence` | Optional, all records | Finite number from 0 through 1; booleans and null are rejected |
| `evidence` | Optional, all records | Array of inert evidence reference objects; defaults to an empty array |

Each evidence object requires nonempty text `ref`. It may contain nonempty text `kind` and a `metadata` JSON object. Metadata may contain nested objects, arrays, strings, finite numbers, booleans, and null. Its complete JSON values are preserved in observation details. Object key order and whitespace are insignificant; array order and repeated evidence entries are preserved. Missing `kind` or `metadata` remains missing in details. References may describe local files, captures, URLs, or other source identifiers; none is opened or interpreted.

Unknown envelope, observation, and evidence fields are rejected. Ambiguous duplicate object keys anywhere, malformed JSON, invalid Unicode, and nonfinite numbers (`NaN`, `Infinity`, overflowed numeric literals) are rejected. Validation errors identify the one-based observation index where applicable. Identifiers and source labels retain their exact text; they are not case-folded or trimmed. Empty or whitespace-only text and ASCII control characters are rejected for bounded text fields.

## Normalization, identity, and provenance

Hostname normalization reuses `core.recon.targets.normalize_hostname`: lowercasing, removing one trailing dot, and IDNA canonicalization, with the existing strict hostname validation. Hostname records cannot contain IP addresses, URLs, paths, credentials, ports, or wildcards. IP literals use `ipaddress.ip_address(...).compressed`; scoped addresses such as `fe80::1%eth0`, bracketed IP input, and ambiguous IPv4 spellings are rejected. Service hosts use the same hostname or IP normalization. Normalization is entirely offline.

Stable asset keys are:

| Asset | Key example |
| --- | --- |
| Hostname | `recon:hostname:example.com` |
| IPv4 | `recon:ip:192.0.2.10` |
| IPv6 | `recon:ip:2001:db8::10` |
| TCP service | `recon:service:tcp:example.com:443` |
| IPv6 UDP service | `recon:service:udp:[2001:db8::10]:443` |

Service identity includes canonical host, transport, and port. Names such as `https` and `tls` enrich one service asset when those identity fields match. TCP and UDP at the same host and port remain distinct. Hostname assets remain distinct even when their evidence mentions the same IP address. Importing a service does not create a host asset, and importing evidence does not create an address asset or relation.

Observation identity is `(run_id, source, id)`. Repeated identical normalized records with that identity coalesce. A different normalized payload under the same identity rejects the entire import, including conflicts with records already in memory. Producers should supply a new `run_id` for a new run or a distinct record `id` for another observation. Distinct IDs, sources, or runs remain separate observations even when they enrich the same asset. Missing evidence and an empty evidence array normalize equally; numeric confidence `1` and `1.0` normalize equally.

An asset stores all observations, sorted by `(run_id, source, id)`, with their normalized values, confidence, source, run, record ID, and evidence. Sources and service names are sorted unique summaries. `evidence_count` counts unique complete evidence objects, including `ref`, optional `kind`, and full optional metadata, across that asset's observations. It does not count repeated identical objects twice. Evidence object key order does not change uniqueness.

## Limits and atomic behavior

| Limit | Maximum |
| --- | --- |
| Input text or file size | 8 MiB of UTF-8 bytes |
| Observations in one document, including duplicates | 10,000 |
| Evidence references per observation | 32 |
| Run ID, record ID, source, evidence kind, service name | 128 characters each |
| Evidence reference | 1024 characters |
| Raw hostname or service host | 1024 characters, plus existing hostname limits |
| Raw IP value | 128 characters |
| One evidence metadata object | 4096 UTF-8 bytes in compact JSON with sorted keys |
| Metadata container nesting | 8 levels, counting the metadata root object as level 1 |
| General JSON nesting within one observation | 16 levels |

File reads request at most 8 MiB plus one byte, so the limit remains effective if a file grows. Remote URL, UNC, Windows device, and reserved device-name paths are rejected before file access. Only `.json` files are supported. A successful file read does not authorize following any paths contained in it.

The parser fully validates a document before returning records. `AssetInventory` checks all stored identity conflicts and builds the next snapshot before changing state. A failed import leaves existing observations and assets unchanged. Exact repeated imports add no observations; an empty import preserves the current inventory. The inventory is in memory only and adds no persistent session format or authorization, severity, or vulnerability flags.

## Python API

```python
from core.recon.inventory import AssetInventory
from core.recon.observations import ObservationImportError

inventory = AssetInventory()
try:
    result = inventory.import_file("tests/fixtures/recon_observations_v1.json")
except ObservationImportError as error:
    print(str(error))
else:
    print(result.added_observations, result.duplicates, result.total_assets, result.run_id)
    details = inventory.assets[0].to_dict()
```

`import_json(text)` has the same result contract. `assets` is an immutable tuple sorted by `entity_key`; `observations` is an immutable tuple sorted by source identity. Assets and observations are frozen values. Their `to_dict()` methods return independent, JSON-safe details, including complete normalized observations and evidence. `Observation.to_dict()` includes `run_id`, `id`, `source`, `type`, `entity_key`, normalized `value` (or service `host`, `transport`, `port`), optional `service_name` and `confidence`, and an `evidence` array. `parse_observations_json(text)` and `read_observations_file(path)` are also available without an inventory.

The synthetic fixture contains seven observations representing six assets: two hostnames, IPv4, IPv6, TCP/443, and UDP/443. `example.com` has two observations from separate sources. All fixture addresses and evidence are synthetic.
