"""Explicit finite-scope Nmap controls within the shared Recon inspector."""

import re

from PySide6.QtCore import QObject, Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QGroupBox, QLabel, QMessageBox, QPlainTextEdit,
    QPushButton, QSizePolicy, QVBoxLayout,
)

from core.recon.nmap_capabilities import capability_reasons
from core.recon.nmap_profiles import configuration_arguments, format_network_impact
from core.recon.nmap_scope import scope_is_fresh
from core.recon.nmap_scope_preflight import NmapScopePreflight
from dialogs.results_viewer_dialog import UniversalViewerDialog


class NmapAuthorizedControls(QObject):
    def __init__(self, recon):
        super().__init__(recon)
        self._recon = recon
        self._runtime = recon.nmap_runtime
        self.preflight = NmapScopePreflight(self)
        self._caps = None
        self._caps_identity = None
        self._revision = 0
        self._scope_shown = None
        self._build_ui()
        self.preflight.changed.connect(self._scope_changed)
        self._runtime.changed.connect(self.refresh)
        recon.ui.nmapProfileSelector.currentIndexChanged.connect(self._invalidate)
        recon.ui.btnStopNmap.clicked.connect(self._stop_preflight)
        self.refresh()

    @staticmethod
    def _label(text=""):
        label = QLabel(text)
        label.setTextFormat(Qt.PlainText)
        label.setWordWrap(True)
        label.setMinimumWidth(0)
        label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        return label

    def _build_ui(self):
        ui = self._recon.ui
        ui.nmapAuthorizedSetup = QGroupBox("Authorized Profile Scan")
        layout = QVBoxLayout(ui.nmapAuthorizedSetup)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.addWidget(self._label("Uses the selected profile above. Target Manager and discovered assets grant no authorization."))
        ui.nmapScopeInput = QPlainTextEdit()
        ui.nmapScopeInput.setPlaceholderText("Hostnames, IPs, exact CIDRs or full IP ranges; one per line")
        ui.nmapScopeInput.setMaximumHeight(95)
        ui.nmapScopeInput.setAccessibleName("Explicit Nmap scope targets")
        layout.addWidget(ui.nmapScopeInput)
        ui.btnNmapUseSelected = QPushButton("Use checked targets")
        ui.btnNmapUseSelected.clicked.connect(self._use_selected)
        layout.addWidget(ui.btnNmapUseSelected)
        ui.nmapScopeFamily = QComboBox()
        ui.nmapScopeFamily.addItem("IPv4", 4)
        ui.nmapScopeFamily.addItem("IPv6", 6)
        ui.nmapScopeFamily.setToolTip("Select the DNS address family to authorize. Mixed families require separate runs.")
        layout.addWidget(ui.nmapScopeFamily)
        ui.btnNmapScopePreflight = QPushButton("Review concrete scope")
        ui.btnNmapScopePreflight.clicked.connect(self._preflight)
        layout.addWidget(ui.btnNmapScopePreflight)
        ui.nmapScopeStatus = self._label()
        layout.addWidget(ui.nmapScopeStatus)
        ui.nmapConcreteScope = QPlainTextEdit()
        ui.nmapConcreteScope.setReadOnly(True)
        ui.nmapConcreteScope.setMaximumHeight(110)
        ui.nmapConcreteScope.setAccessibleName("Complete concrete target scope")
        layout.addWidget(ui.nmapConcreteScope)
        layout.addWidget(self._label("I authorize every concrete address shown for this run."))
        ui.nmapScopeApproval = QCheckBox("I authorize scope")
        ui.nmapScopeApproval.setAccessibleName("I authorize every concrete address shown for this run")
        ui.nmapScopeApproval.setToolTip("Explicit permission must cover the complete concrete range, including CIDR boundary addresses.")
        ui.nmapScopeApproval.toggled.connect(self.refresh)
        layout.addWidget(ui.nmapScopeApproval)
        ui.btnNmapCapabilities = QPushButton("Inspect capabilities")
        ui.btnNmapCapabilities.setToolTip("Inspect Windows, verified Nmap, Npcap, privileges and IPv6 capabilities without changing the system.")
        ui.btnNmapCapabilities.clicked.connect(self._inspect_capabilities)
        layout.addWidget(ui.btnNmapCapabilities)
        ui.nmapCapabilities = self._label("Read-only capability inspection required before execution.")
        layout.addWidget(ui.nmapCapabilities)
        ui.nmapAuthorizedPreview = QPlainTextEdit()
        ui.nmapAuthorizedPreview.setReadOnly(True)
        ui.nmapAuthorizedPreview.setMaximumHeight(110)
        ui.nmapAuthorizedPreview.setAccessibleName("Effective authorized Nmap arguments")
        layout.addWidget(ui.nmapAuthorizedPreview)
        ui.nmapAuthorizedImpact = self._label()
        layout.addWidget(ui.nmapAuthorizedImpact)
        ui.toolInfo.section_layouts["profiles"].addWidget(ui.nmapAuthorizedSetup)
        ui.btnNmapAuthorizedRun = QPushButton("Run Authorized Profile…")
        ui.btnNmapAuthorizedRun.clicked.connect(self._confirm)
        ui.toolInfo.section_layouts["execution"].addWidget(ui.btnNmapAuthorizedRun)
        ui.nmapAuthorizedStatus = self._label()
        ui.toolInfo.section_layouts["results"].addWidget(ui.nmapAuthorizedStatus)
        ui.btnNmapAuthorizedResults = QPushButton("Open results / evidence")
        ui.btnNmapAuthorizedResults.clicked.connect(self._open_results)
        ui.toolInfo.section_layouts["results"].addWidget(ui.btnNmapAuthorizedResults)
        ui.nmapScopeInput.textChanged.connect(self._invalidate)
        ui.nmapScopeFamily.currentIndexChanged.connect(self._invalidate)

    def set_visible(self, visible):
        ui = self._recon.ui
        for widget in (ui.nmapAuthorizedSetup, ui.btnNmapAuthorizedRun,
                       ui.nmapAuthorizedStatus, ui.btnNmapAuthorizedResults):
            widget.setVisible(visible)

    def _profile(self):
        return self._recon.public_nmap_controls._selected_profile()

    def _inputs(self):
        return tuple(part for part in re.split(r"[,\s]+", self._recon.ui.nmapScopeInput.toPlainText().strip()) if part)

    def _invalidate(self, *_args):
        self._revision += 1
        self._recon.ui.nmapScopeApproval.setChecked(False)
        self.preflight.clear()

    def _use_selected(self):
        self._recon.ui.nmapScopeInput.setPlainText("\n".join(self._recon.public_nmap_controls._selected_targets()))

    def _preflight(self):
        if self._runtime.busy:
            return
        self._recon.ui.nmapScopeApproval.setChecked(False)
        self.preflight.start(self._inputs(), family=self._recon.ui.nmapScopeFamily.currentData())

    def _stop_preflight(self):
        if self.preflight.busy:
            self.preflight.clear()

    def _scope_changed(self):
        scope = self.preflight.scope
        if scope is not self._scope_shown:
            self._scope_shown = scope
            self._revision += 1
            self._recon.ui.nmapScopeApproval.setChecked(False)
        self._recon.ui.nmapConcreteScope.setPlainText("\n".join(scope.targets) if scope else "")
        self._recon.ui.nmapScopeStatus.setText(self.preflight.status)
        self.refresh()
        self._recon._refresh_nmap_runtime()

    def _inspect_capabilities(self):
        try:
            self._caps = self._runtime.capabilities()
            self._caps_identity = self._capability_identity()
        except (ValueError, OSError, RuntimeError) as error:
            self._caps = None
            self._caps_identity = None
            self._recon.ui.nmapCapabilities.setText(str(error))
        self._revision += 1
        self._recon.ui.nmapScopeApproval.setChecked(False)
        self.refresh()

    def _capability_identity(self):
        tool = getattr(self._runtime, "_tool", None)
        return (self._runtime.executable_path, self._runtime.version, getattr(tool, "sha256", ""))

    def _reasons(self):
        profile = self._profile()
        if profile is None:
            return ("Select a saved profile.",)
        reasons = list(capability_reasons(profile, self._caps))
        scope = self.preflight.scope
        if scope and scope.family == 6 and self._caps and not self._caps.ipv6:
            reasons.append("IPv6 is unavailable on this system.")
        return tuple(reasons)

    def _arguments(self):
        profile, scope = self._profile(), self.preflight.scope
        if profile is None:
            return ()
        if scope is not None and hasattr(self._runtime, "authorized_arguments"):
            return self._runtime.authorized_arguments(scope, profile)
        return (*configuration_arguments(profile), "<explicitly-approved-addresses>")

    def refresh(self):
        ui, runtime = self._recon.ui, self._runtime
        if self._caps is not None and self._caps_identity != self._capability_identity():
            self._caps = None
            self._caps_identity = None
            self._revision += 1
            ui.nmapCapabilities.setText("Nmap executable changed; inspect Windows capabilities again.")
            ui.nmapScopeApproval.setChecked(False)
        scope, profile = self.preflight.scope, self._profile()
        idle = not runtime.busy and not self.preflight.busy
        fresh = scope is not None and scope_is_fresh(scope)
        for widget in (ui.nmapScopeInput, ui.nmapScopeFamily, ui.btnNmapUseSelected, ui.btnNmapCapabilities):
            widget.setEnabled(idle)
        ui.btnNmapScopePreflight.setEnabled(idle and bool(self._inputs()))
        ui.nmapScopeApproval.setEnabled(idle and fresh)
        reasons = self._reasons()
        if self._caps:
            caps = self._caps
            ui.nmapCapabilities.setText(
                f"Windows: {caps.windows}; verified Nmap: {caps.version or 'unavailable'}\n"
                f"Npcap: {caps.npcap}; elevated: {caps.elevated}; raw packets: {caps.raw_packets}; IPv6: {caps.ipv6}\n"
                + ("\n".join(caps.reasons) + "\n" if caps.reasons else "")
                + ("Execution blocked: " + " ".join(reasons) if reasons else "Configuration is executable with these observed capabilities; launch rechecks them.")
            )
        try:
            arguments = self._arguments()
            # Structured arguments are never echoed into logs or evidence. The
            # editable values remain visible only in the profile configuration.
            preview = list(arguments)
            for index, value in enumerate(preview[:-1]):
                if value == "--script-args":
                    preview[index + 1] = "<structured-values-redacted>"
            ui.nmapAuthorizedPreview.setPlainText(" ".join(preview))
            preview_error = ""
        except (ValueError, OSError, RuntimeError) as error:
            preview_error = str(error)
            ui.nmapAuthorizedPreview.setPlainText("Plan unavailable: " + preview_error)
        ui.nmapAuthorizedImpact.setText(format_network_impact(profile) if profile else "")
        ui.btnNmapAuthorizedRun.setEnabled(bool(idle and runtime.can_run and fresh
            and ui.nmapScopeApproval.isChecked() and not reasons and not preview_error))
        ui.nmapAuthorizedStatus.setText(runtime.status)
        ui.btnNmapAuthorizedResults.setEnabled(bool(getattr(runtime, "last_authorized_result", None)))

    def _confirm(self):
        ui = self._recon.ui
        if not ui.btnNmapAuthorizedRun.isEnabled():
            return
        profile, scope, revision = self._profile(), self.preflight.scope, self._revision
        try:
            arguments = self._arguments()
        except (ValueError, OSError, RuntimeError) as error:
            ui.nmapAuthorizedStatus.setText(f"Plan rejected: {error}")
            return
        high_impact = False
        version_nse_confirmed = False
        if profile.version_detection:
            try:
                version_scripts = self._runtime.implicit_version_scripts()
            except (ValueError, OSError, RuntimeError) as error:
                ui.nmapScopeApproval.setChecked(False)
                ui.nmapAuthorizedStatus.setText(f"Version engine unavailable: {error}")
                return
            risky_version_scripts = tuple(script.script_id for script in version_scripts if script.high_impact)
            answer = QMessageBox.warning(self._recon, "Confirm version engine probes",
                "Nmap service-version detection (-sV) also runs the installed NSE version engine scripts.\n"
                "These active probes use the same approved numeric scope and bounded installation.\n"
                f"Version scripts: {', '.join(script.script_id for script in version_scripts) or 'none installed'}\n"
                + (f"HIGH IMPACT scripts: {', '.join(risky_version_scripts)}. These may disrupt services.\n"
                   "I additionally approve these high-impact version probes.\n" if risky_version_scripts else "")
                +
                "I explicitly approve the version engine scripts and service probes for this run.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes:
                ui.nmapScopeApproval.setChecked(False)
                return
            version_nse_confirmed = True
            high_impact = bool(risky_version_scripts)
        if profile.script_ids:
            # Every script requires active consent. Potentially disruptive and
            # unsupported script classes are checked again by the trusted plan.
            answer = QMessageBox.warning(self._recon, "Confirm NSE script execution",
                "NSE executes active code from the verified installation. Intrusive, brute, exploit and dos scripts can disrupt services.\n"
                f"Selected scripts: {', '.join(profile.script_ids)}\n"
                "Scope-limited scripts and structured arguments are revalidated before launch.\n"
                "I explicitly approve the impact of these scripts for this run.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes:
                ui.nmapScopeApproval.setChecked(False)
                return
            high_impact = True
        answer = QMessageBox.question(self._recon, "Confirm authorized Nmap scan",
            f"Profile: {profile.name}\nComplete scope: {scope.target_count} IPv{scope.family} addresses\n"
            + "\n".join(scope.targets) + "\n\nArguments:\n" + ui.nmapAuthorizedPreview.toPlainText()
            + "\n\n" + format_network_impact(profile)
            + "\n\nI have permission for every address shown and approve this exact scan now.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        unchanged = (scope is self.preflight.scope and scope_is_fresh(scope)
            and revision == self._revision and profile == self._profile() and not self._runtime.busy
            and self._runtime.can_run)
        ui.nmapScopeApproval.setChecked(False)
        if answer != QMessageBox.Yes:
            return
        try:
            if not unchanged or self._arguments() != arguments:
                raise ValueError("Scope, profile, executable or preflight changed; review this run again.")
            self._recon.public_nmap_controls._saved_profile_unchanged(profile)
            self._runtime.start_authorized_scan(scope, profile=profile,
                profile_store=self._recon.nmap_profile_store, scope_confirmed=True,
                confirmed=True, high_impact_confirmed=high_impact,
                version_nse_confirmed=version_nse_confirmed)
        except (ValueError, OSError, RuntimeError) as error:
            self.preflight.clear()
            ui.nmapAuthorizedStatus.setText(f"Authorized scan rejected: {error}")
        else:
            self.preflight.clear()

    def _open_results(self):
        result = getattr(self._runtime, "last_authorized_result", None)
        if result is not None:
            UniversalViewerDialog(title="Nmap scan results and evidence", payload=result,
                parent=self._recon, default_save_stem="nmap_evidence").exec()
