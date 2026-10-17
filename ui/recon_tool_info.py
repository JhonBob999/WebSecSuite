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
            "Discover open TCP services with the implemented Local Self-Test. "
            "WebSecSuite supports only this fixed localhost profile; it does not "
            "scan imported targets."
        ),
        "installation": (
            "Choose an official signed Windows nmap.exe. Approval checks local "
            "identity and cached certificate trust before a bounded version check. "
            "Nothing is downloaded or installed."
        ),
        "profiles": (
            "Local Self-Test: TCP connect to 127.0.0.1, ports 80, 443, 8080, 8443. "
            "No arbitrary options, external targets, scripts, UDP, OS detection "
            "or service-version probing."
        ),
        "network": (
            "Local TCP connections only; DNS and host discovery are disabled. "
            "Requested maximum: 10 probes/s, one retry. Host timeout: 30 s; "
            "overall timeout: 40 s. Local services may log connections."
        ),
        "execution": (
            "Requires verified Nmap, Windows process containment and fresh "
            "confirmation for each run. Stop cancels the current operation."
        ),
        "results": (
            "Validated successful results add the loopback IP and open TCP "
            "services to Asset Inventory and Run / Import History. Zero open "
            "ports is valid. Existing offline Nmap XML import remains available."
        ),
    },
    "subfinder": {
        "overview": (
            "Find subdomain names through passive external sources. Typical "
            "recon use: expand a domain's candidate attack surface. Coverage "
            "depends on source data and configured provider credentials; names "
            "are not proof of live or authorized assets."
        ),
        "installation": (
            "WebSecSuite detects local native candidates only: compatibility "
            "unverified; version not verified; adapter not connected. No "
            "installation or provider configuration is performed here."
        ),
        "profiles": "None implemented in WebSecSuite; execution options unavailable.",
        "network": (
            "When run independently, passive discovery queries external data "
            "providers, whose rate limits and logging apply. Review domain "
            "authorization and provider terms. WebSecSuite detection here reads "
            "local metadata only; no network requests."
        ),
        "execution": "Execution disabled. No Subfinder runtime or Stop action is connected.",
        "results": (
            "No Subfinder contributions to Asset Inventory or run history "
            "currently; detection reports only a local candidate."
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
