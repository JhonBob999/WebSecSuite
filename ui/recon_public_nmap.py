"""Narrow public Nmap UI; DNS observations never confer scan authorization."""

from PySide6.QtCore import QObject, QSignalBlocker, Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QLabel, QMessageBox, QPushButton, QSizePolicy,
    QVBoxLayout, QWidget,
)

from core.recon.targets import normalize_hostname
from core.recon.nmap_profile_execution import execution_reasons, validate_executable_profile
from core.recon.nmap_profile_store import NmapProfileStore
from core.recon.nmap_profiles import format_network_impact, format_ports


class NmapPublicControls(QObject):
    """Keep per-attempt scope confirmation separate from imported target scope."""

    def __init__(self, recon):
        super().__init__(recon)
        self._recon = recon
        self._runtime = recon.nmap_runtime
        self._preflight = self._runtime.public_preflight
        self._selected = self._selected_targets()
        self._shown_observation = None
        self._confirmation_revision = 0
        self._profiles = {}
        self._build_ui()
        self.reload_profiles()
        recon.target_model.inventoryChanged.connect(self._targets_changed)
        self._preflight.changed.connect(self._preflight_changed)
        self._runtime.changed.connect(self.refresh_runtime)
        self._preflight_changed()

    @staticmethod
    def _label(text=""):
        label = QLabel(text)
        label.setTextFormat(Qt.PlainText)
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        label.setMinimumWidth(0)
        return label

    def _build_ui(self):
        ui = self._recon.ui
        ui.nmapProfileSetup = QWidget()
        profiles = QVBoxLayout(ui.nmapProfileSetup)
        profiles.setContentsMargins(0, 0, 0, 0)
        profiles.addWidget(self._label("Scan Profile"))
        ui.nmapProfileSelector = QComboBox()
        ui.nmapProfileSelector.setAccessibleName("Nmap scan profile")
        ui.nmapProfileSelector.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        ui.nmapProfileSelector.setMinimumWidth(0)
        ui.nmapProfileSelector.currentIndexChanged.connect(self._profile_changed)
        profiles.addWidget(ui.nmapProfileSelector)
        ui.nmapProfileSummary = self._label()
        profiles.addWidget(ui.nmapProfileSummary)
        ui.nmapProfileEligibility = self._label()
        profiles.addWidget(ui.nmapProfileEligibility)
        ui.toolInfo.section_layouts["profiles"].addWidget(ui.nmapProfileSetup)
        ui.nmapPublicSetup = QWidget()
        layout = QVBoxLayout(ui.nmapPublicSetup)
        layout.setContentsMargins(0, 0, 0, 0)
        ui.nmapPublicTarget = self._label()
        layout.addWidget(ui.nmapPublicTarget)
        ui.btnNmapPreflight = QPushButton("Public Target Preflight")
        ui.btnNmapPreflight.setToolTip("Resolve only the checked ginandjuice.shop target; DNS does not grant authorization.")
        ui.btnNmapPreflight.clicked.connect(self._start_preflight)
        layout.addWidget(ui.btnNmapPreflight)
        ui.nmapPublicDns = self._label("Resolved IPv4 addresses: not resolved\nCNAME: not available")
        layout.addWidget(ui.nmapPublicDns)
        ui.nmapPublicIp = QComboBox()
        ui.nmapPublicIp.setAccessibleName("Selected public IPv4 address")
        ui.nmapPublicIp.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        ui.nmapPublicIp.setMinimumWidth(0)
        ui.nmapPublicIp.addItem("Select one resolved IPv4…", None)
        ui.nmapPublicIp.currentIndexChanged.connect(self._ip_changed)
        layout.addWidget(ui.nmapPublicIp)
        ui.nmapPublicSelectedIp = self._label("Selected IP: none")
        layout.addWidget(ui.nmapPublicSelectedIp)
        ui.nmapPublicWarning = self._label(
            "DNS is not authorization. Confirm permission for the selected IP; domain permission may not cover shared infrastructure."
        )
        layout.addWidget(ui.nmapPublicWarning)
        # Put long explanatory text in a wrapping label; QCheckBox text itself
        # cannot wrap within the user-resizable narrow inspector.
        ui.nmapPublicScope = QCheckBox("I confirm IP scope")
        ui.nmapPublicScope.setAccessibleName("I confirm authorization to scan the selected public IP")
        ui.nmapPublicScope.setToolTip("I confirm that this exact selected IPv4 address is within my authorized scanning scope for this run.")
        ui.nmapPublicScope.toggled.connect(self.refresh_runtime)
        layout.addWidget(ui.nmapPublicScope)
        ui.nmapPublicScopeStatus = self._label()
        layout.addWidget(ui.nmapPublicScopeStatus)
        ui.nmapPublicStatus = self._label()
        layout.addWidget(ui.nmapPublicStatus)
        ui.toolInfo.section_layouts["profiles"].addWidget(ui.nmapPublicSetup)
        ui.btnNmapPublicScan = QPushButton("Public Scan")
        ui.btnNmapPublicScan.setToolTip("Confirm Quick Network Discovery for exactly one approved IPv4 address.")
        ui.btnNmapPublicScan.clicked.connect(self._confirm_scan)
        ui.toolInfo.section_layouts["execution"].addWidget(ui.btnNmapPublicScan)
        ui.btnNmapRunProfile = QPushButton("Run Selected Profile…")
        ui.btnNmapRunProfile.setToolTip("Confirm the selected bounded profile for exactly one authorized public IPv4.")
        ui.btnNmapRunProfile.clicked.connect(self._confirm_profile_scan)
        ui.toolInfo.section_layouts["execution"].addWidget(ui.btnNmapRunProfile)
        ui.nmapPublicSummary = self._label()
        ui.toolInfo.section_layouts["results"].addWidget(ui.nmapPublicSummary)

    def set_visible(self, visible):
        ui = self._recon.ui
        for widget in (ui.nmapPublicSetup, ui.btnNmapPublicScan, ui.nmapPublicSummary,
                       ui.nmapProfileSetup, ui.btnNmapRunProfile):
            widget.setVisible(visible)

    def reload_profiles(self):
        """Refresh saved configuration only; never select an IP or start a run."""
        combo = self._recon.ui.nmapProfileSelector
        selected_id = combo.currentData()
        self._profiles = {profile.profile_id: profile for profile in self._recon.nmap_profile_store.all_profiles}
        with QSignalBlocker(combo):
            combo.clear()
            for profile in self._profiles.values():
                combo.addItem(profile.name, profile.profile_id)
                combo.setItemData(combo.count() - 1, profile.description, Qt.ToolTipRole)
            index = combo.findData(selected_id)
            combo.setCurrentIndex(max(0, index))
        self._profile_changed()

    def _selected_profile(self):
        return self._profiles.get(self._recon.ui.nmapProfileSelector.currentData())

    def _profile_changed(self):
        self._confirmation_revision += 1
        ui, profile = self._recon.ui, self._selected_profile()
        ui.nmapPublicScope.setChecked(False)
        if profile is None:
            ui.nmapProfileSummary.setText("Select a saved scan profile.")
            ui.nmapProfileEligibility.setText("Not executable in R7B-1: no selected profile.")
        else:
            ui.nmapProfileSummary.setText(
                f"Name: {profile.name}\n{profile.description}\n"
                f"TCP ports ({len(profile.ports)}): {format_ports(profile.ports)}\n"
                f"Technique: TCP connect (-sT)\n"
                f"Maximum rate: {profile.max_rate} probes/s; retries: {profile.max_retries}\n"
                f"Host timeout: {profile.host_timeout_seconds} s; "
                f"overall timeout: {profile.execution_timeout_seconds} s\n"
                f"Version detection: {'enabled' if profile.version_detection else 'disabled'}\n"
                f"Network impact: {format_network_impact(profile)}"
            )
            reasons = execution_reasons(profile)
            if profile.profile_id == "quick-network-discovery":
                text = "Use the existing Public Scan action for Quick Network Discovery."
            elif reasons:
                text = " ".join(reasons)
                if "Not executable in R7B-1" not in text:
                    text = "Not executable in R7B-1: " + text
            else:
                text = "Eligible in R7B-1. Fresh DNS, selected IP scope and per-run confirmation are required."
            ui.nmapProfileEligibility.setText(text)
        self.refresh_runtime()

    def _selected_targets(self):
        model = self._recon.target_model
        return tuple(
            model.index(row, model.HOSTNAME).data(Qt.DisplayRole)
            for row in range(model.rowCount())
            if model.index(row, model.SELECT).data(Qt.CheckStateRole) == Qt.Checked
        )

    def _selected_hostname(self):
        selected = self._selected_targets()
        if len(selected) != 1:
            return None
        try:
            hostname = normalize_hostname(selected[0])
        except ValueError:
            return None
        return hostname if hostname == "ginandjuice.shop" else None

    def _targets_changed(self):
        selected = self._selected_targets()
        if selected != self._selected:
            self._selected = selected
            self._confirmation_revision += 1
            self._recon.ui.nmapPublicScope.setChecked(False)
            self._preflight.clear()
        self.refresh_runtime()

    def _preflight_changed(self):
        ui, observation = self._recon.ui, self._preflight.observation
        if observation is not self._shown_observation:
            self._shown_observation = observation
            self._confirmation_revision += 1
            ui.nmapPublicScope.setChecked(False)
            with QSignalBlocker(ui.nmapPublicIp):
                ui.nmapPublicIp.clear()
                ui.nmapPublicIp.addItem("Select one resolved IPv4…", None)
                if observation is not None:
                    for address in observation.ipv4_addresses:
                        ui.nmapPublicIp.addItem(address, address)
        if observation is None:
            ui.nmapPublicDns.setText("Resolved IPv4 addresses: not resolved\nCNAME: not available")
        else:
            ui.nmapPublicDns.setText(
                f"Resolved IPv4 addresses: {', '.join(observation.ipv4_addresses)}\n"
                f"CNAME: {', '.join(observation.cnames) or 'not provided by resolver'}\n"
                f"DNS observation: {observation.observed_at}\nResolver: {observation.resolver}"
            )
        ui.nmapPublicWarning.setText(
            "DNS is not authorization. Confirm permission for the selected IP; domain permission may not cover shared infrastructure."
            + ("\n" + "\n".join(self._preflight.warnings) if self._preflight.warnings else "")
        )
        ui.nmapPublicStatus.setText(self._preflight.status)
        if not self._preflight.is_fresh:
            ui.nmapPublicScope.setChecked(False)
        self.refresh_runtime()

    def _ip_changed(self):
        self._confirmation_revision += 1
        self._recon.ui.nmapPublicScope.setChecked(False)
        self.refresh_runtime()

    def _can_scan(self):
        ui, observation = self._recon.ui, self._preflight.observation
        return bool(
            self._runtime.can_run and not self._runtime.busy and not self._preflight.busy
            and self._preflight.is_fresh and observation is not None
            and self._selected_hostname() == observation.hostname
            and ui.nmapPublicIp.currentData() in observation.ipv4_addresses
            and ui.nmapPublicScope.isChecked()
        )

    def refresh_runtime(self):
        ui, runtime = self._recon.ui, self._runtime
        selected = self._selected_targets()
        ui.nmapPublicTarget.setText("Selected Target: " + (", ".join(selected) if selected else "none"))
        ui.nmapPublicSelectedIp.setText(f"Selected IP: {ui.nmapPublicIp.currentData() or 'none'}")
        ui.btnNmapPreflight.setEnabled(
            self._selected_hostname() is not None and not runtime.busy and not self._preflight.busy
        )
        fresh = self._preflight.is_fresh and self._preflight.observation is not None
        ui.nmapPublicIp.setEnabled(fresh and not runtime.busy and not self._preflight.busy)
        ui.nmapPublicScope.setEnabled(
            fresh and ui.nmapPublicIp.currentData() is not None and not runtime.busy and not self._preflight.busy
        )
        ui.nmapPublicScopeStatus.setText(
            "Scope authorization: confirmed for this attempt" if ui.nmapPublicScope.isChecked()
            else "Scope authorization: required for the exact selected IP"
        )
        ui.btnNmapPublicScan.setEnabled(self._can_scan())
        profile = self._selected_profile()
        eligible = bool(profile is not None and profile.profile_id != "quick-network-discovery"
                        and not execution_reasons(profile))
        ui.nmapProfileSelector.setEnabled(not runtime.busy)
        ui.btnNmapRunProfile.setEnabled(eligible and self._can_scan())
        ui.nmapPublicSummary.setText("Execution / final results: " + runtime.status)

    def _start_preflight(self):
        if not self._recon.ui.btnNmapPreflight.isEnabled():
            return
        self._recon.ui.nmapPublicScope.setChecked(False)
        try:
            self._preflight.start(self._selected_targets())
        except (ValueError, RuntimeError) as error:
            self._recon.ui.nmapPublicStatus.setText(f"Preflight rejected: {error}")
        self.refresh_runtime()

    def _confirm_scan(self):
        if not self._can_scan():
            return
        ui = self._recon.ui
        observation = self._preflight.observation
        address = ui.nmapPublicIp.currentData()
        revision = self._confirmation_revision
        selected = self._selected_targets()
        answer = QMessageBox.question(
            self._recon, "Confirm Nmap Public Scan",
            f"Target: {observation.hostname}\nSelected IP: {address}\n"
            "Profile: Quick Network Discovery\nPorts: 80, 443, 8080, 8443\n"
            "Technique: TCP connect (-sT); no DNS or host discovery\n"
            "Maximum: 10 probes/s, one retry; host timeout 30 s; overall timeout 40 s.\n\n"
            "Network impact: active TCP connections to these four ports on this IP. "
            "The infrastructure may be shared and connections may be logged. "
            "This identifies reachable TCP ports, not verified vulnerabilities.\n\n"
            "I confirm that this exact IP is within my authorized scanning scope. Run this scan?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        # A modal dialog runs an event loop: selection, DNS expiry or executable
        # state can change while the confirmation is displayed.
        unchanged = (
            self._can_scan() and self._preflight.observation is observation
            and ui.nmapPublicIp.currentData() == address
            and self._confirmation_revision == revision and self._selected_targets() == selected
        )
        ui.nmapPublicScope.setChecked(False)
        if answer != QMessageBox.Yes:
            return
        if not unchanged:
            ui.nmapPublicStatus.setText("Preflight changed or expired; review the target and IP again.")
            self.refresh_runtime()
            return
        try:
            self._runtime.start_public_scan(
                self._selected_targets(), address=address, scope_confirmed=True, confirmed=True,
            )
        except (ValueError, RuntimeError) as error:
            ui.nmapPublicStatus.setText(f"Public Scan rejected: {error}")
        self.refresh_runtime()

    def _saved_profile_unchanged(self, profile):
        if profile.is_builtin:
            return
        store = NmapProfileStore(self._recon.nmap_profile_store.path)
        if store.load_error or not any(saved == profile for saved in store.profiles):
            raise ValueError("Saved profile changed or became unavailable; reopen the application and review it again.")

    def _confirm_profile_scan(self):
        ui = self._recon.ui
        if not ui.btnNmapRunProfile.isEnabled() or not self._can_scan():
            return
        try:
            # This fresh frozen snapshot, rather than any preview text, is the
            # entire profile approved by the confirmation below.
            profile = validate_executable_profile(self._selected_profile())
            self._saved_profile_unchanged(profile)
        except ValueError as error:
            ui.nmapPublicScope.setChecked(False)
            ui.nmapPublicStatus.setText(f"Selected Profile rejected: {error}")
            self.refresh_runtime()
            return
        observation = self._preflight.observation
        address = ui.nmapPublicIp.currentData()
        selected = self._selected_targets()
        revision = self._confirmation_revision
        answer = QMessageBox.question(
            self._recon, "Confirm Nmap Scan Profile",
            f"Target: {observation.hostname}\nSelected IP: {address}\n"
            f"Profile: {profile.name}\nTCP ports ({len(profile.ports)}): {format_ports(profile.ports)}\n"
            "Technique: TCP connect (-sT); no DNS or host discovery\n"
            f"Maximum rate: {profile.max_rate} probes/s; retries: {profile.max_retries}\n"
            f"Host timeout: {profile.host_timeout_seconds} s; "
            f"overall timeout: {profile.execution_timeout_seconds} s\n"
            "Version detection: disabled\n\n"
            f"Network impact: {format_network_impact(profile)} "
            "Active TCP connections may be logged and infrastructure may be shared. "
            "Reachable TCP ports are not verified vulnerabilities.\n\n"
            "I confirm that this exact IP is within my authorized scanning scope. Run this scan?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        unchanged = (
            self._can_scan() and self._confirmation_revision == revision
            and self._selected_targets() == selected and self._selected_profile() == profile
            and self._preflight.observation is observation and ui.nmapPublicIp.currentData() == address
        )
        ui.nmapPublicScope.setChecked(False)
        if answer != QMessageBox.Yes:
            return
        if not unchanged:
            ui.nmapPublicStatus.setText("Target, IP, profile or preflight changed or expired; review this run again.")
            self.refresh_runtime()
            return
        try:
            self._saved_profile_unchanged(profile)
            self._runtime.start_profile_scan(
                selected, profile=profile, profile_store=self._recon.nmap_profile_store,
                address=address, scope_confirmed=True, confirmed=True,
            )
        except (ValueError, RuntimeError) as error:
            ui.nmapPublicStatus.setText(f"Selected Profile rejected: {error}")
        self.refresh_runtime()


__all__ = ["NmapPublicControls"]
