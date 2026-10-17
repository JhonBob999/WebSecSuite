"""Bounded inert catalog of the verified installation's NSE scripts.

No Lua is evaluated. Only exact installed basenames are accepted, never user
paths, categories, expressions or script argument files. Arguments have a small
reviewed policy that excludes credentials, new targets, files and commands.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re

from core.recon.tool_discovery import _LocalInspection


MAX_SCRIPTS = 2048
MAX_SCRIPT_BYTES = 2 * 1024 * 1024
MAX_SCRIPT_DATABASE_BYTES = 2 * 1024 * 1024
_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,99}")
_ENTRY = re.compile(r'Entry\s*\{\s*filename\s*=\s*"([^"\r\n]+)"\s*,\s*categories\s*=\s*\{([^{}]*)\}\s*,?\s*\}', re.S)
_HIGH_IMPACT = frozenset({"intrusive", "brute", "exploit", "dos", "fuzzer", "malware"})
_CROSS_SCOPE = frozenset({"broadcast", "external"})
_KNOWN_HIGH_IMPACT_IDS = frozenset({"ssl-enum-ciphers", "ssl-dh-params", "http-enum", "iec61850-mms"})
# -sV implicitly loads these installed version scripts. Unknown future version
# scripts remain catalog-only until their target behavior has been reviewed.
VERSION_SCRIPT_IDS = frozenset({
    "allseeingeye-info", "amqp-info", "bacnet-info", "cccam-version", "db2-das-info",
    "docker-version", "drda-info", "enip-info", "fingerprint-strings", "fox-info",
    "freelancer-info", "hnap-info", "http-server-header", "http-trane-info", "https-redirect",
    "iax2-version", "iec61850-mms", "ike-version", "jdwp-version", "maxdb-info",
    "mcafee-epo-agent", "mikrotik-routeros-version", "mqtt-subscribe", "murmur-version",
    "ndmp-version", "netbus-version", "omron-info", "openlookup-info", "oracle-tns-version",
    "ovs-agent-version", "pptp-version", "quake1-info", "quake3-info", "rfc868-time",
    "rpc-grind", "rpcinfo", "s7-info", "skypev2-version", "snmp-info", "stun-version",
    "teamspeak2-version", "tftp-version", "ubiquiti-discovery", "ventrilo-info", "vmware-version",
    "wdb-version", "weblogic-t3-info", "xmpp-info",
})
SUPPORTED_SCRIPT_IDS = frozenset({
    "banner", "http-title", "http-headers", "http-server-header", "http-security-headers",
    "http-methods", "http-enum", "http-cookie-flags", "http-robots.txt", "http-auth-finder",
    "ssl-cert", "ssl-date", "ssl-enum-ciphers", "ssl-dh-params", "tls-alpn", "tls-nextprotoneg",
    "ssh-hostkey", "ssh2-enum-algos", "dns-recursion", "dns-nsid",
    "ftp-anon", "ftp-syst", "smtp-commands", "smtp-ntlm-info", "pop3-capabilities",
    "imap-capabilities", "mysql-info", "rdp-ntlm-info", "rdp-enum-encryption",
    "smb-os-discovery", "smb-protocols", "smb-security-mode", "smb2-security-mode", "smb2-time",
}) | VERSION_SCRIPT_IDS


@dataclass(frozen=True, slots=True)
class ScriptInfo:
    script_id: str
    categories: tuple[str, ...]
    description: str
    sha256: str
    path: str
    supported: bool = True
    unsupported_reason: str = ""

    @property
    def id(self):
        return self.script_id

    @property
    def high_impact(self):
        return self.script_id in _KNOWN_HIGH_IMPACT_IDS or bool(_HIGH_IMPACT.intersection(self.categories))


def distribution_directory(tool) -> Path:
    from core.recon.nmap_adapter import _validate_tool
    _validate_tool(tool)
    return _LocalInspection(os.name == "nt").path(Path(tool.executable_path).parent, directory=True)


def bounded_file(path, *, limit=MAX_SCRIPT_BYTES) -> bytes:
    try:
        canonical = _LocalInspection(os.name == "nt").path(path)
        with canonical.open("rb") as stream:
            content = stream.read(limit + 1)
        if not content or len(content) > limit:
            raise ValueError
        return content
    except (OSError, ValueError, TypeError):
        raise ValueError("Installed Nmap data is missing, unsafe, empty or exceeds the inspection limit.") from None


def _description(content):
    text = content.decode("utf-8", "replace")
    match = re.search(r'description\s*=\s*\[\[(.*?)\]\]', text, re.S)
    if match is None:
        match = re.search(r'description\s*=\s*"([^"\r\n]*)"', text)
    value = " ".join(match[1].split()) if match else "Installed NSE script; review its documented behavior before execution."
    return "".join(character for character in value if ord(character) >= 32)[:2000]


def discover_scripts(tool) -> tuple[ScriptInfo, ...]:
    root = distribution_directory(tool)
    directory = root / "scripts"
    if not directory.exists():
        return ()
    directory = _LocalInspection(os.name == "nt").path(directory, directory=True)
    raw = bounded_file(directory / "script.db", limit=MAX_SCRIPT_DATABASE_BYTES)
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("Installed NSE script database is not valid UTF-8.") from None
    entries = list(_ENTRY.finditer(text))
    if not entries or len(entries) > MAX_SCRIPTS or _ENTRY.sub("", text).strip():
        raise ValueError("Installed NSE script database is malformed or exceeds catalog limits.")
    scripts = []
    seen = set()
    for entry in entries:
        filename = entry[1]
        script_id = filename[:-4] if filename.endswith(".nse") else ""
        if _NAME.fullmatch(script_id) is None or ".." in script_id or script_id in seen:
            raise ValueError("NSE catalog contains an unsafe path, duplicate or unsupported script identity.")
        categories = tuple(sorted(set(re.findall(r'"([a-z][a-z-]{0,31})"', entry[2]))))
        if not categories or re.sub(r'"[a-z][a-z-]{0,31}"|[\s,]', "", entry[2]):
            raise ValueError("Installed NSE categories are malformed.")
        path = directory / filename
        content = bounded_file(path)
        # The file's static categories supplement script.db; risk cannot be
        # downgraded merely by editing its database entry.
        category_match = re.search(rb'(?m)^\s*categories\s*=\s*\{([^{}]*)\}', content)
        if category_match:
            static_categories = re.findall(rb'"([a-z][a-z-]{0,31})"', category_match[1])
            categories = tuple(sorted(set(categories) | {value.decode("ascii") for value in static_categories}))
        reason = "" if script_id in SUPPORTED_SCRIPT_IDS else "This installed script has not been reviewed for exact numeric target scope; catalog inspection only."
        if _CROSS_SCOPE.intersection(categories):
            reason = "Broadcast/external scripts can contact addresses outside the approved concrete scope."
        if re.search(rb"\b(?:target\s*\.\s*add|newtargets)\b", content):
            reason = "Scripts that add new scan targets are unsupported."
        # Numeric targets and -n are mandatory for supported HTTP scripts: the
        # installed HTTP library's default redirects then require exact host.ip.
        scripts.append(ScriptInfo(script_id, categories, _description(content),
            hashlib.sha256(content).hexdigest(), str(path), not bool(reason), reason))
        seen.add(script_id)
    return tuple(sorted(scripts, key=lambda item: item.script_id))


def validate_scripts(tool, scripts) -> tuple[ScriptInfo, ...]:
    if type(scripts) is not tuple or len(scripts) > 128 or any(type(item) is not ScriptInfo for item in scripts):
        raise ValueError("Explicit and implicit version NSE selection exceeds the bounded installed script limit.")
    current = {item.script_id: item for item in discover_scripts(tool)}
    for script in scripts:
        if current.get(script.script_id) != script:
            raise ValueError("An installed NSE script or catalog changed; review the selection again.")
        if not script.supported:
            raise ValueError(script.unsupported_reason)
    if len({item.script_id for item in scripts}) != len(scripts):
        raise ValueError("NSE selection contains duplicate scripts.")
    return scripts


SCRIPT_ARGUMENT_HELP = (
    "Reviewed arguments: http.max-body-size (1–1048576), http.max-pipeline (1–16), "
    "http.pipeline (1–16), http.useragent (letters/digits/spaces and ._()-), "
    "ssh_hostkey (full/sha256/md5/bubble/visual/all), banner.timeout (1–30 seconds). "
    "Other arguments are unsupported."
)


def validate_script_arguments(arguments) -> tuple[tuple[str, str], ...]:
    if type(arguments) is not tuple or len(arguments) > 16:
        raise ValueError("NSE arguments must be at most 16 structured name/value pairs.")
    names = set()
    for pair in arguments:
        if type(pair) is not tuple or len(pair) != 2 or any(type(item) is not str for item in pair):
            raise ValueError("NSE arguments require exact text name/value pairs.")
        name, value = pair
        if name in names:
            raise ValueError("NSE argument names must be unique.")
        names.add(name)
        valid = False
        if name in {"http.max-body-size", "http.max-pipeline", "http.pipeline", "banner.timeout"}:
            maximum = 1_048_576 if name == "http.max-body-size" else 16
            if name == "banner.timeout":
                maximum = 30
            valid = bool(re.fullmatch(r"[0-9]{1,7}", value)) and 1 <= int(value) <= maximum
        elif name == "ssh_hostkey":
            valid = value in {"full", "sha256", "md5", "bubble", "visual", "all"}
        elif name == "http.useragent":
            valid = bool(re.fullmatch(r"[A-Za-z0-9 ._()-]{1,128}", value))
        if not valid:
            raise ValueError("Unsupported or unsafe NSE argument. " + SCRIPT_ARGUMENT_HELP)
    return arguments
