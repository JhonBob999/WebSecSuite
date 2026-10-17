"""Passive Subfinder setup and one-attempt scope controls for the shared inspector."""

from pathlib import Path

from PySide6.QtCore import QObject, Qt
from PySide6.QtWidgets import (
    QFileDialog, QLabel, QMessageBox, QPushButton, QSizePolicy, QVBoxLayout, QWidget,
)

from core.recon.execution_policy import ScopeApproval
from core.recon.subfinder_adapter import PROFILE, selected_subfinder_hostname


class SubfinderControls(QObject):
    """Keep executable approval and ephemeral domain scope independent of Nmap."""

    def __init__(self, recon):
        super().__init__(recon)
        self._recon = recon
        self._runtime = recon.subfinder_runtime
        self._executable = ""
        self._archive = ""
        self._notice = ""
        self._selection_revision = self._runtime_revision = self._setup_revision = 0
        self._approved_setup_revision = 0
        self._verification_requested_revision = None
        self._scope_revision = 0
        self._scope_approval = ScopeApproval()
        self._build_ui()
        recon.target_model.inventoryChanged.connect(self._targets_changed)
        self._runtime.changed.connect(self._runtime_changed)
        self.refresh_runtime()

    @property
    def scope_approval(self):
        """Application exclusions only; stored positive grants never authorize a run."""
        return self._scope_approval

    @scope_approval.setter
    def scope_approval(self, value):
        if type(value) is not ScopeApproval:
            raise TypeError("Subfinder scope policy must be a ScopeApproval.")
        self._scope_approval = value
        self._scope_revision += 1
        self.refresh_runtime()

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
        ui.subfinderInstallation = QWidget()
        installation = QVBoxLayout(ui.subfinderInstallation)
        installation.setContentsMargins(0, 0, 0, 0)
        ui.subfinderExecutableLabel = self._label()
        ui.subfinderArchiveLabel = self._label()
        ui.subfinderVersionLabel = self._label()
        ui.subfinderAdapterLabel = self._label()
        for label in (ui.subfinderExecutableLabel, ui.subfinderArchiveLabel,
                      ui.subfinderVersionLabel, ui.subfinderAdapterLabel):
            installation.addWidget(label)
        ui.btnChooseSubfinder = QPushButton("Choose Subfinder…")
        ui.btnChooseSubfinder.setToolTip("Choose an absolute local subfinder.exe path; selection runs nothing.")
        ui.btnChooseSubfinder.clicked.connect(self._choose_executable)
        ui.btnChooseSubfinderArchive = QPushButton("Choose official archive…")
        ui.btnChooseSubfinderArchive.setToolTip("Choose the official v2.17.0 Windows amd64 or arm64 release ZIP already on disk.")
        ui.btnChooseSubfinderArchive.clicked.connect(self._choose_archive)
        ui.btnApproveSubfinder = QPushButton("Verify / approve executable")
        ui.btnApproveSubfinder.setToolTip("Confirm pinned release verification before a contained version check.")
        ui.btnApproveSubfinder.clicked.connect(self._confirm_executable)
        for button in (ui.btnChooseSubfinder, ui.btnChooseSubfinderArchive, ui.btnApproveSubfinder):
            installation.addWidget(button)
        ui.toolInfo.section_layouts["installation"].addWidget(ui.subfinderInstallation)

        ui.subfinderTargetLabel = self._label()
        ui.toolInfo.section_layouts["profiles"].addWidget(ui.subfinderTargetLabel)
        ui.subfinderExecution = QWidget()
        execution = QVBoxLayout(ui.subfinderExecution)
        execution.setContentsMargins(0, 0, 0, 0)
        ui.subfinderStatusLabel = self._label()
        execution.addWidget(ui.subfinderStatusLabel)
        ui.btnRunSubfinder = QPushButton("Run Passive Discovery")
        ui.btnRunSubfinder.setToolTip("Confirm scope for exactly one checked hostname for this attempt.")
        ui.btnRunSubfinder.clicked.connect(self._confirm_discovery)
        ui.btnStopSubfinder = QPushButton("Stop Subfinder")
        ui.btnStopSubfinder.clicked.connect(self._runtime.stop)
        execution.addWidget(ui.btnRunSubfinder)
        execution.addWidget(ui.btnStopSubfinder)
        ui.toolInfo.section_layouts["execution"].addWidget(ui.subfinderExecution)

        ui.subfinderResults = QWidget()
        results = QVBoxLayout(ui.subfinderResults)
        results.setContentsMargins(0, 0, 0, 0)
        ui.subfinderResultLabel = self._label()
        results.addWidget(ui.subfinderResultLabel)
        ui.btnSubfinderHistory = QPushButton("Run / Import History")
        ui.btnSubfinderHistory.clicked.connect(self._show_history)
        results.addWidget(ui.btnSubfinderHistory)
        ui.toolInfo.section_layouts["results"].addWidget(ui.subfinderResults)

    def set_visible(self, visible):
        ui = self._recon.ui
        for widget in (ui.subfinderInstallation, ui.subfinderTargetLabel,
                       ui.subfinderExecution, ui.subfinderResults):
            widget.setVisible(visible)

    def _selected_targets(self):
        model = self._recon.target_model
        return tuple(
            model.index(row, model.HOSTNAME).data(Qt.DisplayRole)
            for row in range(model.rowCount())
            if model.index(row, model.SELECT).data(Qt.CheckStateRole) == Qt.Checked
        )

    def _selected_hostname(self):
        model = self._recon.target_model
        if any(model.index(row, model.VALIDATION).data(Qt.DisplayRole) != "Valid"
               for row in range(model.rowCount())
               if model.index(row, model.SELECT).data(Qt.CheckStateRole) == Qt.Checked):
            return None
        try:
            return selected_subfinder_hostname(self._selected_targets())
        except ValueError:
            return None

    def _excluded(self, hostname):
        policy = self.scope_approval
        return hostname in policy.excluded_domains or any(
            hostname.endswith("." + root) for root in policy.excluded_subdomain_ranges
        )

    def _targets_changed(self):
        # Revisions also reject A -> B -> A changes while a modal event loop runs.
        self._selection_revision += 1
        self.refresh_runtime()

    def _runtime_changed(self):
        self._runtime_revision += 1
        self._notice = ""
        if (self._verification_requested_revision == self._setup_revision
                and self._runtime.can_run and not self._runtime.busy
                and Path(self._runtime.executable_path) == Path(self._executable)):
            self._approved_setup_revision = self._setup_revision
        self.refresh_runtime()

    def _can_discover(self):
        hostname = self._selected_hostname()
        return bool(hostname and not self._excluded(hostname)
                    and self._runtime.can_run and not self._runtime.busy
                    and self._approved_setup_revision == self._setup_revision
                    and (not self._executable
                         or Path(self._runtime.executable_path) == Path(self._executable)))

    def _snapshot(self):
        runtime = self._runtime
        return (self._selection_revision, self._runtime_revision, self._setup_revision,
                self._scope_revision, self._selected_targets(), runtime.executable_path,
                runtime.version, runtime.can_run, runtime.busy)

    def refresh_runtime(self):
        ui, runtime = self._recon.ui, self._runtime
        ui.subfinderExecutableLabel.setText(
            f"Chosen executable: {self._executable or 'none'}\n"
            f"Validated executable: {runtime.executable_path or 'not validated'}"
        )
        ui.subfinderArchiveLabel.setText(f"Official release ZIP: {self._archive or 'none'}")
        ui.subfinderVersionLabel.setText(f"Subfinder version: {runtime.version or 'not verified'}")
        ui.subfinderAdapterLabel.setText(
            f"Adapter unavailable: {runtime.safety_reason}" if runtime.safety_reason
            else "Adapter available · bounded passive discovery"
        )
        selected, hostname = self._selected_targets(), self._selected_hostname()
        requirement = ("Excluded by application scope policy." if hostname and self._excluded(hostname)
                       else "Fresh scope confirmation required for each run." if hostname
                       else "Check exactly one valid Target Manager hostname.")
        ui.subfinderTargetLabel.setText(
            "Selected target: " + (", ".join(selected) if selected else "none") + "\n" + requirement
        )
        ui.subfinderStatusLabel.setText(self._notice or runtime.status)
        ui.subfinderResultLabel.setText("Execution / final results: " + runtime.status)
        ui.btnChooseSubfinder.setEnabled(not runtime.busy)
        ui.btnChooseSubfinderArchive.setEnabled(not runtime.busy)
        ui.btnApproveSubfinder.setEnabled(bool(self._executable and self._archive and not runtime.busy))
        ui.btnRunSubfinder.setEnabled(self._can_discover())
        ui.btnStopSubfinder.setEnabled(runtime.busy)

    def _pick_path(self, *, archive):
        if self._runtime.busy:
            return
        snapshot = self._snapshot()
        path, _ = QFileDialog.getOpenFileName(
            self._recon,
            "Choose official Subfinder v2.17.0 Windows release ZIP" if archive else "Choose Subfinder executable",
            self._archive if archive else self._executable,
            "ZIP archives (*.zip)" if archive else "Windows executable (*.exe)",
        )
        if not path:
            return
        if self._snapshot() != snapshot or self._runtime.busy:
            self._notice = "Setup changed; choose the file again."
        elif not Path(path).is_absolute():
            self._notice = "Choose an absolute local file path."
        else:
            if archive:
                self._archive = path
            else:
                self._executable = path
            self._setup_revision += 1
            self._approved_setup_revision = self._verification_requested_revision = None
            self._notice = "Selected files are not approved; verify the executable explicitly."
        self.refresh_runtime()

    def _choose_executable(self):
        self._pick_path(archive=False)

    def _choose_archive(self):
        self._pick_path(archive=True)

    def _confirm_executable(self):
        if not self._recon.ui.btnApproveSubfinder.isEnabled():
            return
        executable, archive, snapshot = self._executable, self._archive, self._snapshot()
        answer = QMessageBox.question(
            self._recon, "Approve Subfinder executable verification",
            f"Executable: {executable}\nOfficial release ZIP: {archive}\n\n"
            "Required provenance: official ProjectDiscovery Subfinder v2.17.0 Windows "
            "amd64 or arm64 GitHub release. The local ZIP must match the application-pinned "
            "SHA-256 release digest, and the executable must match its ZIP member.\n\n"
            "If those checks pass, run only a contained, bounded version check. "
            "This runs local third-party code. Nothing is downloaded or installed, "
            "and this approval grants no domain scope. Approve this executable check?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        if self._snapshot() != snapshot or self._runtime.busy:
            self._notice = "Setup or runtime changed; review the executable and ZIP again."
        else:
            self._notice = ""
            self._approved_setup_revision = None
            self._verification_requested_revision = self._setup_revision
            try:
                self._runtime.approve_executable(executable, archive_path=archive)
            except (OSError, ValueError, RuntimeError) as error:
                self._verification_requested_revision = None
                self._notice = f"Subfinder verification rejected: {error}"
        self.refresh_runtime()

    def _confirm_discovery(self):
        if not self._can_discover():
            return
        hostname, snapshot, policy = self._selected_hostname(), self._snapshot(), self.scope_approval
        answer = QMessageBox.question(
            self._recon, "Confirm Subfinder Passive Discovery",
            f"Selected root: {hostname}\nProfile: {PROFILE} (passive subdomain discovery)\n"
            "Fixed limits: -rl 2 (2 requests/s), -timeout 15 (seconds), "
            "-max-time 2 (minutes); application timeout 150 seconds.\n\n"
            "Network impact: third-party API requests disclose this root to external "
            "data providers and may be logged; provider terms apply. User provider "
            "configuration and credentials are not loaded, so source coverage is limited. "
            "No active resolution, recursion, all-sources mode, custom flags, HTTP probing "
            "or automatic scans of discovered names. Names are unverified candidates.\n\n"
            "I confirm that this exact root is within my authorized scope for this run "
            "and approve these passive requests. Run discovery?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        if self._snapshot() != snapshot or not self._can_discover():
            self._notice = "Target, scope or runtime changed; review and confirm a new attempt."
        else:
            # Never retain a positive authorization on the controls or target model.
            approval = ScopeApproval(
                exact_domains=(hostname,), excluded_domains=policy.excluded_domains,
                excluded_subdomain_ranges=policy.excluded_subdomain_ranges,
            )
            self._notice = ""
            try:
                self._runtime.start_discovery(self._selected_targets(), confirmed=True, approval=approval)
            except (ValueError, RuntimeError) as error:
                self._notice = f"Subfinder discovery rejected: {error}"
        self.refresh_runtime()

    def _show_history(self):
        self._recon.ui.reconPages.setCurrentIndex(1)
        self._recon.ui.importHistory.setFocus()


__all__ = ["SubfinderControls"]
