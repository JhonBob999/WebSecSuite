"""Recon target management, asset inventory and explicitly authorized Nmap profiles."""

from collections import Counter
from types import SimpleNamespace

from PySide6.QtCore import QModelIndex, QSignalBlocker, Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QFileDialog, QFrame, QGroupBox, QHBoxLayout, QHeaderView,
    QInputDialog, QLabel, QLineEdit, QMenu, QMessageBox, QPlainTextEdit, QPushButton,
    QScrollArea, QSizePolicy, QSplitter, QStackedWidget, QTableView, QTabWidget, QVBoxLayout, QWidget,
)

from core.recon.inventory import AssetInventory
from core.recon.nmap_profile_store import NmapProfileStore
from core.recon.nmap_runtime import NmapRuntime
from core.recon.subfinder_runtime import SubfinderRuntime
from core.recon.observations import ObservationImportError
from core.recon.tool_discovery import ToolDiscoveryService
from core.recon.targets import (
    ImportIssue, ImportReport, TargetRecord, csv_columns, normalize_hostname,
    parse_text, read_target_file, read_target_text,
)
from dialogs.results_viewer_dialog import UniversalViewerDialog
from dialogs.nmap_profiles_dialog import NmapProfilesDialog
from ui.recon_asset_model import ReconAssetFilterProxy, ReconAssetModel
from ui.recon_target_model import ImportIssueModel, ReconTargetModel
from ui.recon_tool_info import TOOL_NAMES, ToolInformationView
from ui.recon_public_nmap import NmapPublicControls
from ui.recon_subfinder import SubfinderControls


class ReconTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = SimpleNamespace()
        self.target_model = ReconTargetModel(self)
        self.issue_model = ImportIssueModel(self)
        self.asset_inventory = AssetInventory()
        self.asset_model = ReconAssetModel(self)
        self.asset_proxy = ReconAssetFilterProxy(self)
        self.asset_proxy.setSourceModel(self.asset_model)
        self.tool_discovery = ToolDiscoveryService()
        self.nmap_profile_store = NmapProfileStore()
        self._nmap_profiles_dialog = None
        self.nmap_runtime = NmapRuntime(self.asset_inventory, self)
        self.subfinder_runtime = SubfinderRuntime(self.asset_inventory, self)
        self._nmap_candidate_path = ""
        self._tool_inspector_width = 340
        self._build_ui()
        self.target_model.inventoryChanged.connect(self._update_counts)
        self.target_model.editRejected.connect(self.ui.statusLabel.setText)
        self.ui.btnAddTarget.clicked.connect(self._add_manual)
        self.ui.manualInput.returnPressed.connect(self._add_manual)
        self.ui.btnAddPaste.clicked.connect(self._add_paste)
        self.ui.btnImportTxt.clicked.connect(lambda: self._pick_file("txt"))
        self.ui.btnImportCsv.clicked.connect(lambda: self._pick_file("csv"))
        self.ui.btnSelectAll.clicked.connect(lambda: self.target_model.set_all_selected(True))
        self.ui.btnDeselectAll.clicked.connect(lambda: self.target_model.set_all_selected(False))
        self.ui.btnRemoveSelected.clicked.connect(self.target_model.remove_selected)
        self.ui.btnClearTargets.clicked.connect(self._confirm_clear)
        self.ui.btnImportObservations.clicked.connect(self._pick_observations_file)
        self.ui.btnImportNmap.clicked.connect(self._pick_nmap_file)
        self.ui.assetSearch.textChanged.connect(self._apply_asset_filters)
        self.ui.assetTypeFilter.currentIndexChanged.connect(self._apply_asset_filters)
        self.ui.sourceFilter.currentIndexChanged.connect(self._apply_asset_filters)
        self.ui.importHistory.currentIndexChanged.connect(self._apply_asset_filters)
        self.ui.btnResetFilters.clicked.connect(self._reset_asset_filters)
        self.ui.btnResetView.clicked.connect(self._reset_asset_view)
        self.ui.assetTable.customContextMenuRequested.connect(self._show_asset_context_menu)
        self.ui.assetTable.selectionModel().selectionChanged.connect(self._update_asset_details_button)
        self.ui.btnAssetDetails.clicked.connect(self._open_asset_details)
        self.ui.assetTable.doubleClicked.connect(self._open_asset_details)
        self.ui.btnRefreshDetection.clicked.connect(self._refresh_tool_detection)
        self.ui.btnToolInspectorToggle.clicked.connect(self._toggle_tool_inspector)
        self.ui.btnToggleInvalidTargets.clicked.connect(self._toggle_invalid_targets)
        self.ui.toolSelector.currentIndexChanged.connect(self._select_inspector_tool)
        self.ui.btnChooseNmap.clicked.connect(self._choose_nmap_executable)
        self.ui.btnManageNmapProfiles.clicked.connect(self._open_nmap_profiles)
        self.ui.btnNmapSelfTest.clicked.connect(self._confirm_nmap_self_test)
        self.ui.btnStopNmap.clicked.connect(self.nmap_runtime.stop)
        self.nmap_runtime.changed.connect(self._refresh_nmap_runtime)
        self.nmap_runtime.inventory_changed.connect(self._refresh_asset_inventory)
        self.subfinder_runtime.inventory_changed.connect(self._refresh_asset_inventory)
        self._update_counts()
        self._update_asset_counts()
        self._refresh_tool_detection()
        self._refresh_nmap_runtime()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        toolbar = QHBoxLayout()
        toolbar.addStretch(1)
        self.ui.btnToolInspectorToggle = QPushButton("Hide Tool Inspector")
        self.ui.btnToolInspectorToggle.setAccessibleName("Hide Tool Inspector")
        self.ui.btnToolInspectorToggle.setToolTip("Hide or restore the shared Recon tool panel.")
        toolbar.addWidget(self.ui.btnToolInspectorToggle)
        root.addLayout(toolbar)
        self.ui.reconSplitter = QSplitter(Qt.Horizontal)
        self.ui.reconSplitter.setChildrenCollapsible(False)
        self.ui.reconSplitter.setHandleWidth(6)
        self.ui.reconPages = QTabWidget()
        self.ui.reconSplitter.addWidget(self.ui.reconPages)
        root.addWidget(self.ui.reconSplitter, 1)
        target_page = QWidget()
        self.ui.reconPages.addTab(target_page, "Target Manager")
        layout = QVBoxLayout(target_page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(8)
        title = QLabel("Recon · Target Manager")
        title.setStyleSheet("font-size: 22px; font-weight: 600;")
        layout.addWidget(title)
        note = QLabel(
            "Offline imported targets, separate from discovered assets. "
            "Selection does not grant authorization for active scanning; scope remains unreviewed."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        entry = QGroupBox("Add targets")
        entry_layout = QVBoxLayout(entry)
        manual = QHBoxLayout()
        self.ui.manualInput = QLineEdit()
        self.ui.manualInput.setPlaceholderText("Hostname only, e.g. example.com")
        self.ui.manualInput.setAccessibleName("Single target hostname")
        self.ui.btnAddTarget = QPushButton("Add target")
        self.ui.btnImportTxt = QPushButton("Import TXT…")
        self.ui.btnImportCsv = QPushButton("Import CSV…")
        manual.addWidget(self.ui.manualInput, 1)
        for button in (self.ui.btnAddTarget, self.ui.btnImportTxt, self.ui.btnImportCsv):
            manual.addWidget(button)
        entry_layout.addLayout(manual)
        paste = QHBoxLayout()
        self.ui.pasteInput = QPlainTextEdit()
        self.ui.pasteInput.setPlaceholderText("Paste hostnames, one per line (no URLs, ports or credentials)")
        self.ui.pasteInput.setAccessibleName("Multiline target hostnames")
        self.ui.pasteInput.setFixedHeight(64)
        self.ui.pasteInput.setTabChangesFocus(True)
        self.ui.btnAddPaste = QPushButton("Add paste")
        paste.addWidget(self.ui.pasteInput, 1)
        paste.addWidget(self.ui.btnAddPaste)
        entry_layout.addLayout(paste)
        layout.addWidget(entry)

        actions = QHBoxLayout()
        self.ui.btnSelectAll = QPushButton("Select all")
        self.ui.btnDeselectAll = QPushButton("Deselect all")
        self.ui.btnRemoveSelected = QPushButton("Remove selected")
        self.ui.btnRemoveSelected.setToolTip("Remove targets checked in the Selected column.")
        self.ui.btnClearTargets = QPushButton("Clear list…")
        for button in (self.ui.btnSelectAll, self.ui.btnDeselectAll,
                       self.ui.btnRemoveSelected, self.ui.btnClearTargets):
            actions.addWidget(button)
        actions.addStretch(1)
        self.ui.countLabel = QLabel()
        actions.addWidget(self.ui.countLabel)
        layout.addLayout(actions)

        self.ui.targetTable = QTableView()
        self.ui.targetTable.setAccessibleName("Imported target inventory")
        self.ui.targetTable.setModel(self.target_model)
        self.ui.targetTable.setAlternatingRowColors(True)
        self.ui.targetTable.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.ui.targetTable.setWordWrap(False)
        self.ui.targetTable.verticalHeader().setDefaultSectionSize(26)
        self.ui.targetTable.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.ui.targetTable.horizontalHeader().setStretchLastSection(True)
        for column, width in enumerate((80, 300, 80, 240, 120)):
            self.ui.targetTable.setColumnWidth(column, width)
        layout.addWidget(self.ui.targetTable, 1)

        self.ui.importSummary = QLabel("Added: 0 · Duplicates: 0 · Invalid: 0")
        layout.addWidget(self.ui.importSummary)
        invalid_header = QHBoxLayout()
        self.ui.invalidCountLabel = QLabel("Invalid Targets: 0")
        self.ui.invalidCountLabel.hide()
        self.ui.btnToggleInvalidTargets = QPushButton("Hide Invalid Targets")
        self.ui.btnToggleInvalidTargets.setAccessibleName("Hide Invalid Targets")
        self.ui.btnToggleInvalidTargets.setToolTip("Hide or show rejected rows from the last import.")
        self.ui.btnToggleInvalidTargets.hide()
        invalid_header.addWidget(self.ui.invalidCountLabel)
        invalid_header.addStretch(1)
        invalid_header.addWidget(self.ui.btnToggleInvalidTargets)
        layout.addLayout(invalid_header)
        self.ui.issueTable = QTableView()
        self.ui.issueTable.setAccessibleName("Rejected rows from last import")
        self.ui.issueTable.setModel(self.issue_model)
        self.ui.issueTable.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.ui.issueTable.setWordWrap(False)
        self.ui.issueTable.verticalHeader().hide()
        self.ui.issueTable.horizontalHeader().setStretchLastSection(True)
        self.ui.issueTable.setColumnWidth(0, 55)
        self.ui.issueTable.setColumnWidth(1, 280)
        self.ui.issueTable.setMinimumHeight(70)
        self.ui.issueTable.setMaximumHeight(110)
        self.ui.issueTable.hide()
        layout.addWidget(self.ui.issueTable)
        self.ui.statusLabel = QLabel("Double-click a hostname to edit. Checkboxes select targets for future analysis.")
        self.ui.statusLabel.setTextFormat(Qt.PlainText)
        self.ui.statusLabel.setWordWrap(True)
        layout.addWidget(self.ui.statusLabel)

        self._build_asset_inventory()
        self.ui.reconSplitter.addWidget(self._build_tool_manager())
        self.ui.reconSplitter.setStretchFactor(0, 1)
        self.ui.reconSplitter.setStretchFactor(1, 0)
        self.ui.reconSplitter.setSizes([1000, self._tool_inspector_width])

    def _build_tool_manager(self):
        self.ui.toolManager = QGroupBox("Tool Inspector")
        tools_layout = QVBoxLayout(self.ui.toolManager)
        tools_layout.setSpacing(8)
        self.ui.toolDetectionStatus = QLabel("Detection is read-only; Nmap and Subfinder require setup and confirmation.")
        self.ui.toolDetectionStatus.setTextFormat(Qt.PlainText)
        self.ui.toolDetectionStatus.setWordWrap(True)
        self.ui.toolDetectionStatus.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        tools_layout.addWidget(self.ui.toolDetectionStatus)
        self.ui.btnRefreshDetection = QPushButton("Refresh Detection")
        self.ui.btnRefreshDetection.setToolTip("Inspect local executable paths without running programs.")
        tools_layout.addWidget(self.ui.btnRefreshDetection)
        self.ui.toolSelector = QComboBox()
        self.ui.toolSelector.setAccessibleName("Tool Inspector tool")
        self.ui.toolSelector.setToolTip("Choose a tool to review its information and available controls.")
        self.ui.toolSelector.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        for tool_id, name in TOOL_NAMES.items():
            self.ui.toolSelector.addItem(name, tool_id)
        tools_layout.addWidget(self.ui.toolSelector)
        self.ui.toolInspectorScroll = QScrollArea()
        self.ui.toolInspectorScroll.setAccessibleName("Tool Inspector details")
        self.ui.toolInspectorScroll.setWidgetResizable(True)
        self.ui.toolInspectorScroll.setFrameShape(QFrame.NoFrame)
        self.ui.toolInfo = ToolInformationView()
        self.ui.toolInspectorScroll.setWidget(self.ui.toolInfo)
        tools_layout.addWidget(self.ui.toolInspectorScroll, 1)
        self.ui.toolStatusStack = QStackedWidget()
        self.ui.toolInfo.section_layouts["installation"].addWidget(self.ui.toolStatusStack)
        self.ui.toolLabels = {}
        for tool_id, name in TOOL_NAMES.items():
            label = QLabel(f"{name} — Not detected")
            label.setTextFormat(Qt.PlainText)
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
            self.ui.toolLabels[tool_id] = label
            self.ui.toolStatusStack.addWidget(label)
        self.ui.toolDiagnostic = QLabel()
        self.ui.toolDiagnostic.setTextFormat(Qt.PlainText)
        self.ui.toolDiagnostic.setWordWrap(True)
        self.ui.toolDiagnostic.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.ui.toolDiagnostic.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.ui.toolInfo.section_layouts["installation"].addWidget(self.ui.toolDiagnostic)
        self.ui.nmapInstallation = QWidget()
        installation = QVBoxLayout(self.ui.nmapInstallation)
        installation.setContentsMargins(0, 0, 0, 0)
        self.ui.nmapExecutableLabel = QLabel()
        self.ui.nmapVersionLabel = QLabel()
        self.ui.nmapAdapterLabel = QLabel()
        for detail in (self.ui.nmapExecutableLabel, self.ui.nmapVersionLabel, self.ui.nmapAdapterLabel):
            detail.setTextFormat(Qt.PlainText)
            detail.setWordWrap(True)
            detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
            detail.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
            installation.addWidget(detail)
        self.ui.toolInfo.section_layouts["installation"].addWidget(self.ui.nmapInstallation)
        self.ui.btnManageNmapProfiles = QPushButton("Manage Scan Profiles…")
        self.ui.btnManageNmapProfiles.setToolTip("Edit offline Nmap configuration; starts no scans.")
        self.ui.toolInfo.section_layouts["profiles"].addWidget(self.ui.btnManageNmapProfiles)
        self.ui.nmapExecution = QWidget()
        execution = QVBoxLayout(self.ui.nmapExecution)
        execution.setContentsMargins(0, 0, 0, 0)
        self.ui.nmapStatusLabel = QLabel()
        self.ui.nmapStatusLabel.setTextFormat(Qt.PlainText)
        self.ui.nmapStatusLabel.setWordWrap(True)
        self.ui.nmapStatusLabel.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.ui.nmapStatusLabel.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        execution.addWidget(self.ui.nmapStatusLabel)
        self.ui.btnChooseNmap = QPushButton("Choose Nmap…")
        self.ui.btnChooseNmap.setToolTip("Approve a local nmap.exe path for a contained version check.")
        execution.addWidget(self.ui.btnChooseNmap)
        self.ui.btnNmapSelfTest = QPushButton("Local Self-Test")
        self.ui.btnNmapSelfTest.setEnabled(False)
        self.ui.btnStopNmap = QPushButton("Stop")
        self.ui.btnStopNmap.setEnabled(False)
        for button in (self.ui.btnNmapSelfTest, self.ui.btnStopNmap):
            execution.addWidget(button)
        self.ui.toolInfo.section_layouts["execution"].addWidget(self.ui.nmapExecution)
        self.public_nmap_controls = NmapPublicControls(self)
        self.subfinder_controls = SubfinderControls(self)
        self.subfinder_controls.set_visible(False)
        return self.ui.toolManager

    def _select_inspector_tool(self):
        tool_id = self.ui.toolSelector.currentData()
        self.ui.toolInfo.set_tool(tool_id)
        self.ui.toolStatusStack.setCurrentWidget(self.ui.toolLabels[tool_id])
        self.ui.toolDiagnostic.setText(self.ui.toolLabels[tool_id].toolTip())
        self.ui.nmapInstallation.setVisible(tool_id == "nmap")
        self.ui.nmapExecution.setVisible(tool_id == "nmap")
        self.ui.btnManageNmapProfiles.setVisible(tool_id == "nmap")
        self.public_nmap_controls.set_visible(tool_id == "nmap")
        self.subfinder_controls.set_visible(tool_id == "subfinder")
        self.ui.toolInspectorScroll.verticalScrollBar().setValue(0)

    def _open_nmap_profiles(self):
        if self._nmap_profiles_dialog is None:
            self._nmap_profiles_dialog = NmapProfilesDialog(self.nmap_profile_store, self)
            self._nmap_profiles_dialog.setModal(True)
        self._nmap_profiles_dialog.show()
        self._nmap_profiles_dialog.raise_()
        self._nmap_profiles_dialog.activateWindow()

    def _toggle_tool_inspector(self):
        splitter = self.ui.reconSplitter
        if not self.ui.toolManager.isHidden():
            width = splitter.sizes()[1]
            if width > 0:
                self._tool_inspector_width = width
            self.ui.toolManager.hide()
            splitter.setSizes([1, 0])
            text = "Show Tool Inspector"
        else:
            self.ui.toolManager.show()
            available = splitter.width() - splitter.handleWidth()
            width = self._tool_inspector_width
            splitter.setSizes([max(1, available - width), width])
            text = "Hide Tool Inspector"
        self.ui.btnToolInspectorToggle.setText(text)
        self.ui.btnToolInspectorToggle.setAccessibleName(text)

    def _update_invalid_targets_visibility(self, visible):
        count = self.issue_model.rowCount()
        self.ui.invalidCountLabel.setText(f"Invalid Targets: {count}")
        self.ui.invalidCountLabel.setVisible(bool(count))
        self.ui.btnToggleInvalidTargets.setVisible(bool(count))
        self.ui.issueTable.setVisible(bool(count) and visible)
        text = "Hide Invalid Targets" if count and visible else "Show Invalid Targets"
        self.ui.btnToggleInvalidTargets.setText(text)
        self.ui.btnToggleInvalidTargets.setAccessibleName(text)

    def _toggle_invalid_targets(self):
        self._update_invalid_targets_visibility(self.ui.issueTable.isHidden())

    def _refresh_tool_detection(self):
        self._nmap_candidate_path = ""
        statuses = {
            "NOT_FOUND": "Not found",
            "CANDIDATE_UNVERIFIED": "Candidate found, not verified",
            "INVALID_CANDIDATE": "Invalid candidate",
            "NAME_COLLISION": "Name collision",
        }
        try:
            records = self.tool_discovery.discover()
        except OSError:
            self.ui.toolDetectionStatus.setText("Detection unavailable; execution disabled.")
            for label in self.ui.toolLabels.values():
                name = label.text().split(" — ", 1)[0]
                label.setText(f"{name} — Detection unavailable")
                label.setToolTip("Local executable paths could not be inspected. No program was run.")
            self.ui.toolDiagnostic.setText(self.ui.toolLabels[self.ui.toolSelector.currentData()].toolTip())
            return
        for record in records:
            label = self.ui.toolLabels[record.tool_id]
            path = f" · {record.executable_path}" if record.executable_path else ""
            label.setText(f"{record.display_name} — {statuses[record.status.name]}{path}")
            label.setToolTip(record.diagnostic)
            if record.tool_id == "nmap" and record.status.name == "CANDIDATE_UNVERIFIED":
                self._nmap_candidate_path = record.executable_path or ""
        self.ui.toolDetectionStatus.setText(
            "Detection is read-only; Nmap and Subfinder require setup and confirmation."
        )
        self.ui.toolDiagnostic.setText(self.ui.toolLabels[self.ui.toolSelector.currentData()].toolTip())

    def _refresh_nmap_runtime(self):
        runtime = self.nmap_runtime
        self.ui.nmapExecutableLabel.setText(
            f"Validated executable: {runtime.executable_path or 'Not validated'}"
        )
        self.ui.nmapVersionLabel.setText(f"Nmap version: {runtime.version or 'Not verified'}")
        self.ui.nmapAdapterLabel.setText(
            f"Adapter unavailable: {runtime.safety_reason}" if runtime.safety_reason else
            "Adapter available · Local Self-Test and gated Quick Network Discovery"
        )
        self.ui.nmapStatusLabel.setText(runtime.status)
        self.ui.btnChooseNmap.setEnabled(not runtime.busy)
        self.ui.btnNmapSelfTest.setEnabled(runtime.can_run and not runtime.busy)
        self.ui.btnNmapSelfTest.setToolTip(
            runtime.safety_reason or "Confirm a TCP connect self-test on 127.0.0.1 only."
        )
        self.ui.btnStopNmap.setEnabled(runtime.busy)

    def _choose_nmap_executable(self):
        if self.nmap_runtime.busy:
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose Nmap executable for verification",
            self.nmap_runtime.executable_path or self._nmap_candidate_path,
            "Nmap executable (nmap.exe)",
        )
        if path:
            try:
                self.nmap_runtime.approve_executable(path)
            except (ValueError, RuntimeError) as exc:
                self._refresh_nmap_runtime()
                self.ui.nmapStatusLabel.setText(f"Verification rejected: {exc}")

    def _confirm_nmap_self_test(self):
        if not self.nmap_runtime.can_run or self.nmap_runtime.busy:
            return
        if QMessageBox.question(
            self, "Confirm Nmap Local Self-Test",
            "Target: 127.0.0.1\nPorts: 80, 443, 8080, 8443\n"
            "Technique: TCP connect\n"
            "Possible effect: local TCP connections to the selected ports.\n"
            "No external targets involved.\n\nRun this Local Self-Test?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        try:
            self.nmap_runtime.start_self_test(confirmed=True, target="127.0.0.1")
        except (ValueError, RuntimeError) as exc:
            self._refresh_nmap_runtime()
            self.ui.nmapStatusLabel.setText(f"Local Self-Test rejected: {exc}")

    def closeEvent(self, event):
        self.nmap_runtime.shutdown(immediate=True)
        self.subfinder_runtime.shutdown(immediate=True)
        super().closeEvent(event)

    def _build_asset_inventory(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(8)
        title = QLabel("Recon · Asset Inventory")
        title.setStyleSheet("font-size: 22px; font-weight: 600;")
        layout.addWidget(title)
        note = QLabel(
            "Observations from local JSON, Nmap XML, confirmed Nmap scans or completed Scraper tasks. "
            "Assets remain separate from imported targets; "
            "scope is unreviewed and selection does not authorize active scanning."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        actions = QHBoxLayout()
        self.ui.btnImportObservations = QPushButton("Import Observations JSON…")
        self.ui.btnImportNmap = QPushButton("Import Nmap XML…")
        self.ui.btnAssetDetails = QPushButton("Details")
        self.ui.btnAssetDetails.setEnabled(False)
        actions.addWidget(self.ui.btnImportObservations)
        actions.addWidget(self.ui.btnImportNmap)
        actions.addWidget(self.ui.btnAssetDetails)
        actions.addStretch(1)
        self.ui.assetCountLabel = QLabel()
        actions.addWidget(self.ui.assetCountLabel)
        layout.addLayout(actions)

        history = QHBoxLayout()
        history.addWidget(QLabel("Run / Import History"))
        self.ui.importHistory = QComboBox()
        self.ui.importHistory.setAccessibleName("Asset import history")
        self.ui.importHistory.addItem("All Assets", "")
        history.addWidget(self.ui.importHistory, 1)
        self.ui.btnResetFilters = QPushButton("Reset Filters")
        self.ui.btnResetView = QPushButton("Reset View")
        self.ui.btnResetView.setToolTip("Clear filters and sorting; restore inventory order.")
        history.addWidget(self.ui.btnResetFilters)
        history.addWidget(self.ui.btnResetView)
        layout.addLayout(history)

        filters = QHBoxLayout()
        self.ui.assetSearch = QLineEdit()
        self.ui.assetSearch.setPlaceholderText("Search assets, services or sources")
        self.ui.assetSearch.setAccessibleName("Search asset inventory")
        self.ui.assetSearch.setClearButtonEnabled(True)
        self.ui.assetTypeFilter = QComboBox()
        self.ui.assetTypeFilter.setAccessibleName("Asset type filter")
        for label, entity_type in (("All types", ""), ("Hostname", "hostname"),
                                   ("IP address", "ip"), ("Service", "service")):
            self.ui.assetTypeFilter.addItem(label, entity_type)
        self.ui.sourceFilter = QComboBox()
        self.ui.sourceFilter.setAccessibleName("Observation source filter")
        self.ui.sourceFilter.addItem("All sources", "")
        filters.addWidget(self.ui.assetSearch, 1)
        filters.addWidget(self.ui.assetTypeFilter)
        filters.addWidget(self.ui.sourceFilter)
        layout.addLayout(filters)

        self.ui.assetTable = QTableView()
        self.ui.assetTable.setAccessibleName("Discovered asset inventory")
        self.ui.assetTable.setModel(self.asset_proxy)
        self.ui.assetTable.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.ui.assetTable.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.ui.assetTable.setSelectionMode(QAbstractItemView.SingleSelection)
        self.ui.assetTable.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.assetTable.setAlternatingRowColors(True)
        self.ui.assetTable.setWordWrap(False)
        self.ui.assetTable.verticalHeader().setDefaultSectionSize(26)
        self.ui.assetTable.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.ui.assetTable.horizontalHeader().setStretchLastSection(True)
        for column, width in enumerate((300, 110, 160, 240, 100)):
            self.ui.assetTable.setColumnWidth(column, width)
        self.ui.assetTable.setSortingEnabled(True)
        self.ui.assetTable.sortByColumn(0, Qt.AscendingOrder)
        layout.addWidget(self.ui.assetTable, 1)
        self.ui.assetStatusLabel = QLabel("Import observations to review assets and evidence offline.")
        self.ui.assetStatusLabel.setTextFormat(Qt.PlainText)
        self.ui.assetStatusLabel.setWordWrap(True)
        layout.addWidget(self.ui.assetStatusLabel)
        self.ui.reconPages.addTab(page, "Asset Inventory")

    def _pick_observations_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import observations", "", "JSON files (*.json)",
        )
        if path:
            self.import_observations_file(path)

    def import_observations_file(self, path):
        """Import one validated bundle without disturbing prior state on failure."""
        try:
            result = self.asset_inventory.import_file(path)
        except ObservationImportError as exc:
            self.ui.assetStatusLabel.setText(f"Import failed: {exc}")
            return False
        self._refresh_asset_inventory()
        self.ui.assetStatusLabel.setText(
            f"Added: {result.added_observations} · Duplicates: {result.duplicates} · "
            f"Assets: {result.total_assets}"
        )
        return True

    def _pick_nmap_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Nmap XML", "", "XML files (*.xml)",
        )
        if path:
            self.import_nmap_file(path)

    def import_nmap_file(self, path):
        """Merge a local report using the same atomic inventory and offline viewer."""
        previous_keys = {asset.entity_key for asset in self.asset_inventory.assets}
        previous_identities = {item.identity for item in self.asset_inventory.observations}
        try:
            result = self.asset_inventory.import_nmap_file(path)
        except ObservationImportError as exc:
            self.ui.assetStatusLabel.setText(f"Import failed: {exc}")
            return False
        merged_keys = {
            item.entity_key for item in self.asset_inventory.observations
            if item.identity not in previous_identities and item.entity_key in previous_keys
        }
        self._refresh_asset_inventory()
        self.ui.assetStatusLabel.setText(
            f"Added: {result.added_observations} observations · Duplicates: {result.duplicates} observations · "
            f"New assets: {result.total_assets - len(previous_keys)} · Merged assets: {len(merged_keys)}"
        )
        return True

    def _refresh_asset_inventory(self):
        self._clear_asset_selection()
        self.asset_model.set_assets(self.asset_inventory.assets)
        self._refresh_asset_sources()
        self._refresh_import_history()
        self._apply_asset_filters()

    def _history_labels(self):
        entries = self.asset_inventory.import_history
        labels = {item.import_id: (item.label if item.label == item.format_name
                                  else f"{item.label} · {item.format_name}") for item in entries}
        counts = Counter(labels.values())
        return {item.import_id: (
            f"{labels[item.import_id]} · {item.run_id[:32]} "
            f"[{item.import_id.rsplit(':', 1)[-1][:8]}]"
            if counts[labels[item.import_id]] > 1 else labels[item.import_id]
        ) for item in entries}

    def _refresh_import_history(self):
        selected = self.ui.importHistory.currentData() or ""
        labels = self._history_labels()
        with QSignalBlocker(self.ui.importHistory):
            self.ui.importHistory.clear()
            self.ui.importHistory.addItem("All Assets", "")
            for entry in self.asset_inventory.import_history:
                self.ui.importHistory.addItem(labels[entry.import_id], entry.import_id)
                self.ui.importHistory.setItemData(
                    self.ui.importHistory.count() - 1,
                    f"Run: {entry.run_id}\n{entry.asset_count} assets / "
                    f"{entry.observation_count} observations\nImport: {entry.import_id}", Qt.ToolTipRole,
                )
            self.ui.importHistory.setCurrentIndex(max(0, self.ui.importHistory.findData(selected)))

    def _selected_import(self):
        identity = self.ui.importHistory.currentData()
        return next((item for item in self.asset_inventory.import_history
                     if item.import_id == identity), None)

    def _refresh_asset_sources(self):
        selected_source = self.ui.sourceFilter.currentData() or ""
        sources = sorted({source for asset in self.asset_inventory.assets for source in asset.sources})
        with QSignalBlocker(self.ui.sourceFilter):
            self.ui.sourceFilter.clear()
            self.ui.sourceFilter.addItem("All sources", "")
            for source in sources:
                self.ui.sourceFilter.addItem(source, source)
            selected_index = self.ui.sourceFilter.findData(selected_source)
            self.ui.sourceFilter.setCurrentIndex(max(0, selected_index))
        self.asset_proxy.set_source(self.ui.sourceFilter.currentData() or "")

    def _apply_asset_filters(self, *_args):
        self._clear_asset_selection()
        self.asset_proxy.set_search_text(self.ui.assetSearch.text())
        self.asset_proxy.set_entity_type(self.ui.assetTypeFilter.currentData() or "")
        self.asset_proxy.set_source(self.ui.sourceFilter.currentData() or "")
        entry = self._selected_import()
        self.asset_proxy.set_import_observations(entry.observation_identities if entry else None)
        self._update_asset_counts()

    def _reset_asset_filters(self):
        for widget in (self.ui.assetSearch, self.ui.assetTypeFilter,
                       self.ui.sourceFilter, self.ui.importHistory):
            with QSignalBlocker(widget):
                if widget is self.ui.assetSearch:
                    widget.clear()
                else:
                    widget.setCurrentIndex(0)
        self._apply_asset_filters()

    def _reset_asset_view(self):
        self._reset_asset_filters()
        self.ui.assetTable.sortByColumn(-1, Qt.AscendingOrder)

    def _clear_asset_selection(self):
        self.ui.assetTable.clearSelection()
        self.ui.assetTable.setCurrentIndex(QModelIndex())
        self._update_asset_details_button()

    def _update_asset_counts(self):
        entry = self._selected_import()
        counts = (f"Import: {entry.asset_count} assets / {entry.observation_count} observations"
                  if entry else f"Observations: {len(self.asset_inventory.observations)}")
        self.ui.assetCountLabel.setText(
            f"Total: {self.asset_model.rowCount()} · {counts} · Filtered: {self.asset_proxy.rowCount()}"
        )

    def _update_asset_details_button(self, *_args):
        self.ui.btnAssetDetails.setEnabled(bool(self.ui.assetTable.selectionModel().selectedRows()))

    def _open_asset_details(self, index=None):
        if not isinstance(index, QModelIndex) or not index.isValid():
            selected = self.ui.assetTable.selectionModel().selectedRows()
            if not selected:
                return
            index = selected[0]
        asset = self._asset_for_index(index)
        if asset is not None:
            self._show_asset_details(asset)

    def _asset_for_index(self, index):
        if not index.isValid() or index.model() is not self.asset_proxy:
            return None
        source_index = self.asset_proxy.mapToSource(index)
        asset = self.asset_model.asset_at(source_index.row()) if source_index.isValid() else None
        return asset

    def _show_asset_details(self, asset):
        UniversalViewerDialog(
            title=f"Recon asset: {asset.value}", payload=asset.to_dict(), parent=self,
            show_summary=False, default_save_stem="recon_asset",
        ).exec()

    def _show_asset_context_menu(self, position):
        menu = self._asset_context_menu(self.ui.assetTable.indexAt(position))
        if menu is not None:
            try:
                menu.exec(self.ui.assetTable.viewport().mapToGlobal(position))
            finally:
                menu.deleteLater()

    def _choose_asset_filter(self, combo, value):
        index = combo.findData(value)
        if index >= 0:
            combo.setCurrentIndex(index)

    def _asset_context_menu(self, index):
        """Capture the immutable clicked asset before opening any menu."""
        asset = self._asset_for_index(index)
        if asset is None:
            return None
        menu = QMenu(self)
        menu.setToolTipsVisible(True)
        menu.addAction("Open Asset Details", lambda: self._show_asset_details(asset))
        menu.addAction("Copy Asset Identity", lambda: QApplication.clipboard().setText(asset.entity_key))
        menu.addAction("Filter by Type", lambda: self._choose_asset_filter(
            self.ui.assetTypeFilter, asset.entity_type,
        ))
        sources = menu.addMenu("Filter by Source")
        for source in asset.sources:
            sources.addAction(source, lambda checked=False, value=source: self._choose_asset_filter(
                self.ui.sourceFilter, value,
            ))
        provenance = menu.addMenu("Show related Import / Provenance")
        entries = tuple(item for item in self.asset_inventory.import_history
                        if asset.entity_key in item.entity_keys)
        provenance.addAction("Open Provenance", lambda: self._show_asset_provenance(asset, entries))
        labels = self._history_labels()
        for entry in entries:
            provenance.addAction(labels[entry.import_id], lambda checked=False, value=entry.import_id:
                                 self._choose_asset_filter(self.ui.importHistory, value))
        target = menu.addAction("Add to Target Manager")
        try:
            hostname = normalize_hostname(asset.value)
        except ValueError as exc:
            target.setEnabled(False)
            target.setToolTip(f"R1 accepts hostnames only. {exc}")
        else:
            target.triggered.connect(lambda: self._add_recon_hostname(hostname, "Asset Inventory"))
        return menu

    def _show_asset_provenance(self, asset, entries):
        payload = {
            "entity_key": asset.entity_key,
            "imports": [{"import_id": item.import_id, "label": item.label,
                         "format": item.format_name, "run_id": item.run_id,
                         "asset_count": item.asset_count, "observation_count": item.observation_count}
                        for item in entries],
            "observations": [item.to_dict() for item in asset.observations],
        }
        UniversalViewerDialog(
            title=f"Recon provenance: {asset.value}", payload=payload, parent=self,
            show_summary=False, default_save_stem="recon_provenance",
        ).exec()

    def _add_recon_hostname(self, hostname, source):
        try:
            hostname = normalize_hostname(hostname)
        except ValueError as exc:
            self.ui.statusLabel.setText(f"Transfer rejected: {exc}")
            return False
        self._show_report(ImportReport(targets=[TargetRecord(hostname, source)]))
        return True

    def receive_target_hostname(self, hostname):
        """Receive only a hostname from the Scraper signal, reusing R1 validation."""
        return self._add_recon_hostname(hostname, "Scraper")

    def receive_scraper_observations(self, batch):
        """Receive a bounded factual batch through the shared atomic inventory."""
        try:
            result = self.asset_inventory.import_batch(batch, label="Scraper", format_name="Scraper")
        except (ObservationImportError, ValueError) as exc:
            self.ui.assetStatusLabel.setText(f"Transfer rejected: {exc}")
            return False
        self._refresh_asset_inventory()
        self.ui.assetStatusLabel.setText(
            f"Scraper · Added: {result.added_observations} · Duplicates: {result.duplicates} · "
            "Scope remains unreviewed."
        )
        return True

    def _update_counts(self):
        total, selected = self.target_model.rowCount(), self.target_model.selected_count
        self.ui.countLabel.setText(f"Total: {total} · Selected: {selected}")
        self.ui.btnSelectAll.setEnabled(bool(total))
        self.ui.btnDeselectAll.setEnabled(bool(selected))
        self.ui.btnRemoveSelected.setEnabled(bool(selected))
        self.ui.btnClearTargets.setEnabled(bool(total))

    def _show_report(self, report):
        report = self.target_model.add_report(report)
        self.issue_model.set_issues(report.issues)
        self._update_invalid_targets_visibility(bool(report.issues))
        self.ui.importSummary.setText(
            f"Added: {len(report.targets)} · Duplicates: {report.duplicates} · Invalid: {len(report.issues)}"
        )
        self.ui.statusLabel.setText("Last import is shown above. Scope remains unreviewed.")

    def _add_manual(self):
        value = self.ui.manualInput.text()
        try:
            report = ImportReport(targets=[TargetRecord(normalize_hostname(value), "manual")])
        except ValueError as exc:
            report = ImportReport(issues=[ImportIssue(1, value, str(exc))])
        self._show_report(report)
        if report.targets and not report.issues:
            self.ui.manualInput.clear()

    def _add_paste(self):
        self._show_report(parse_text(self.ui.pasteInput.toPlainText(), "paste"))

    def _pick_file(self, source):
        path, _ = QFileDialog.getOpenFileName(
            self, f"Import {source.upper()} targets", "",
            f"{source.upper()} files (*.{source})",
        )
        if path:
            self.import_file(path, source)

    def import_file(self, path, source, domain_column=None):
        """CSV column choice is explicit; no first-column or URL guessing."""
        if source == "csv" and domain_column is None:
            try:
                text = read_target_text(path)
                if not text.strip():
                    self._show_report(ImportReport())
                    return
                columns = csv_columns(text)
            except (OSError, UnicodeError, ValueError) as exc:
                self._show_report(ImportReport(issues=[ImportIssue(0, str(path), str(exc))]))
                return
            preferred = next((i for i, column in enumerate(columns)
                              if column.lower() in ("domain", "hostname")), 0)
            domain_column, accepted = QInputDialog.getItem(
                self, "CSV domain column", "Column containing hostnames:", columns, preferred, False,
            )
            if not accepted:
                return
        self._show_report(read_target_file(path, source, domain_column))

    def _confirm_clear(self):
        if self.target_model.rowCount() and QMessageBox.question(
            self, "Clear target list", "Remove all imported targets?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) == QMessageBox.Yes:
            self.target_model.clear()
            self.issue_model.set_issues([])
            self._update_invalid_targets_visibility(False)
            self.ui.importSummary.setText("Added: 0 · Duplicates: 0 · Invalid: 0")
            self.ui.statusLabel.setText("Target list cleared.")
