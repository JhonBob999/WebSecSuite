"""Static tool guidance for the Recon inspector; never discovers or runs tools."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QSizePolicy, QVBoxLayout, QWidget


TOOL_NAMES = {
    "nmap": "Nmap",
    "subfinder": "Subfinder",
    "httpx": "ProjectDiscovery httpx",
    "ffuf": "FFUF",
}

_SECTIONS = {
    "overview": "Overview",
    "installation": "Installation / Compatibility",
    "profiles": "Profiles",
    "network": "Network Impact",
    "execution": "Execution",
    "results": "Results",
}

# Generic tool behavior follows the official documentation:
# https://docs.projectdiscovery.io/tools/subfinder/overview
# https://docs.projectdiscovery.io/tools/httpx/overview
# https://github.com/ffuf/ffuf
_TOOL_INFORMATION = {
    "nmap": {
        "overview": (
            "Discover hosts, TCP/UDP ports, services, OS guesses and script evidence using a "
            "saved profile and explicitly authorized concrete scope. Reachability and "
            "fingerprints are observations, not verified vulnerabilities."
        ),
        "installation": (
            "Choose an official signed Windows nmap.exe. Approval checks local "
            "identity and cached certificate trust before a bounded version check. "
            "Nothing is downloaded or installed."
        ),
        "profiles": (
            "Manage Scan Profiles edits typed settings in grouped tabs and never starts a scan. "
            "Authorized Profile Scan supports bounded hostnames, IPv4/IPv6 literals, ranges and CIDRs; "
            "review every numeric address and confirm permission. Capabilities can block a valid "
            "configuration. Local Self-Test and the original ginandjuice.shop Public Scan / "
            "Run Selected Profile actions retain their narrow settings and approval checks."
        ),
        "network": (
            "Active probes may be logged or disrupt services. Rate limits do not reliably bound "
            "version, NSE or discovery probes. Review host/whole-run/script deadlines and concurrency. "
            "-sV also invokes installed NSE version probes and requires extra consent. "
            "Npcap/raw-packet/elevation requirements are inspected read-only; no automatic fallback or elevation."
        ),
        "execution": (
            "Requires verified Nmap, Windows process containment and fresh "
            "scope and per-run confirmation. Extra consent is required for script impact. "
            "Stop cancels the current operation. No hidden scans or automatic retries."
        ),
        "results": (
            "Complete successful XML adds validated IPs and open TCP/UDP services to Asset Inventory "
            "and history. Shared viewers show version/CPE data, OS guesses with confidence, traces, "
            "NSE and provenance. Zero open ports is valid. Failed/partial results are not imported. "
            "DNS and discovered names never grant authorization. Offline XML import remains available."
        ),
    },
    "subfinder": {
        "overview": (
            "Find subdomain names through passive external sources. Typical "
            "recon use: expand a domain's candidate attack surface. Coverage "
            "depends on available source data; names "
            "are not proof of live or authorized assets."
        ),
        "installation": (
            "Choose subfinder.exe and its official v2.17.0 Windows amd64 or arm64 "
            "release ZIP already on disk. Explicit approval checks the pinned "
            "release SHA-256 and executable bytes before a bounded version check. "
            "Nothing is downloaded, installed or configured."
        ),
        "profiles": (
            "Passive Standard: exactly one checked, valid Target Manager hostname. "
            "Confirm authorization for this exact root on every attempt. Exclusions "
            "override confirmation. No active resolution, recursion, all-sources "
            "mode or custom flags."
        ),
        "network": (
            "Passive discovery sends third-party API requests that disclose the "
            "selected root and may be logged. Provider terms and rate limits "
            "apply. User provider configuration and credentials are not loaded; "
            "sources requiring keys are unavailable. Fixed limits: -rl 2 (2 requests/s), -timeout 15 "
            "(seconds), -max-time 2 (minutes); application timeout 150 seconds. "
            "Local detection makes no network requests."
        ),
        "execution": (
            "Requires the verified executable, process containment, one checked "
            "hostname and fresh default-No confirmation of scope and provider "
            "requests. Stop cancels the current operation. Nmap approvals do not "
            "authorize Subfinder."
        ),
        "results": (
            "Validated successful output adds unverified hostname candidates to "
            "Asset Inventory and Run / Import History with Subfinder provenance. "
            "Results do not prove reachability, ownership, authorization or a "
            "vulnerability. Names are not probed or scanned automatically. "
            "Zero results is valid."
        ),
    },
    "httpx": {
        "overview": (
            "Probe web services and collect response metadata such as status, "
            "titles and technology signals. Typical recon use: identify "
            "reachable HTTP services for review. Signals depend on selected "
            "probes and are not confirmed vulnerabilities. This is "
            "ProjectDiscovery httpx, distinct from Python HTTPX."
        ),
        "installation": (
            "WebSecSuite detects local native candidates only: compatibility "
            "unverified; version not verified; adapter not connected. Possible "
            "Python HTTPX launchers are reported as name collisions."
        ),
        "profiles": "None implemented in WebSecSuite; execution options unavailable.",
        "network": (
            "When run independently, probing makes active HTTP(S), DNS and TLS "
            "connections. Requests may be logged; authorization, rate limits "
            "and probe settings matter. WebSecSuite detection here reads local "
            "metadata only; no network requests."
        ),
        "execution": "Execution disabled. No httpx runtime or Stop action is connected.",
        "results": (
            "No httpx contributions to Asset Inventory or run history "
            "currently; detection reports only a local candidate."
        ),
    },
    "ffuf": {
        "overview": (
            "Use wordlists to discover web content and test candidate request "
            "values. Typical recon use: find paths, virtual hosts or parameters "
            "for later review. Results depend on wordlists and response "
            "filtering; matches alone do not establish a vulnerability."
        ),
        "installation": (
            "WebSecSuite detects local native candidates only: compatibility "
            "unverified; version not verified; adapter not connected. No "
            "installation or wordlist configuration is performed here."
        ),
        "profiles": "None implemented in WebSecSuite; execution options unavailable.",
        "network": (
            "When run independently, wordlist fuzzing sends active HTTP(S) "
            "requests and can generate substantial traffic and server logs. "
            "Confirm authorization and control rate and concurrency. "
            "WebSecSuite detection here reads local metadata only; no network requests."
        ),
        "execution": "Execution disabled. No FFUF runtime or Stop action is connected.",
        "results": (
            "No FFUF contributions to Asset Inventory or run history "
            "currently; detection reports only a local candidate."
        ),
    },
}


class ToolInformationView(QWidget):
    """Six static, narrow-width sections with space for existing runtime UI."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.labels = {}
        self.section_layouts = {}
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)
        for key, title in _SECTIONS.items():
            section = QWidget(self)
            section_layout = QVBoxLayout(section)
            section_layout.setContentsMargins(0, 0, 0, 0)
            section_layout.setSpacing(4)
            heading = QLabel(title, section)
            heading.setTextFormat(Qt.PlainText)
            heading.setStyleSheet("font-weight: 600;")
            description = QLabel(section)
            description.setTextFormat(Qt.PlainText)
            description.setWordWrap(True)
            description.setTextInteractionFlags(Qt.TextSelectableByMouse)
            description.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
            description.setMinimumWidth(0)
            section_layout.addWidget(heading)
            section_layout.addWidget(description)
            root.addWidget(section)
            self.labels[key] = description
            self.section_layouts[key] = section_layout
        root.addStretch(1)
        self.set_tool("nmap")

    def set_tool(self, tool_id):
        information = _TOOL_INFORMATION[tool_id]
        for key, label in self.labels.items():
            label.setText(information[key])


__all__ = ["TOOL_NAMES", "ToolInformationView"]
