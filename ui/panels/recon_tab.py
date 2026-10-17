"""Offline Recon target management and imported observation inventory."""

from types import SimpleNamespace

from PySide6.QtCore import QModelIndex, QSignalBlocker, Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QFileDialog, QGroupBox, QHBoxLayout, QHeaderView,
    QInputDialog, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton,
    QTableView, QTabWidget, QVBoxLayout, QWidget,
)

from core.recon.inventory import AssetInventory
from core.recon.observations import ObservationImportError
from core.recon.targets import (
    ImportIssue, ImportReport, TargetRecord, csv_columns, normalize_hostname,
    parse_text, read_target_file, read_target_text,
)
from dialogs.results_viewer_dialog import UniversalViewerDialog
from ui.recon_asset_model import ReconAssetFilterProxy, ReconAssetModel
from ui.recon_target_model import ImportIssueModel, ReconTargetModel


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
        self.ui.assetSearch.textChanged.connect(self._apply_asset_filters)
        self.ui.assetTypeFilter.currentIndexChanged.connect(self._apply_asset_filters)
        self.ui.sourceFilter.currentIndexChanged.connect(self._apply_asset_filters)
        self.ui.assetTable.selectionModel().selectionChanged.connect(self._update_asset_details_button)
        self.ui.btnAssetDetails.clicked.connect(self._open_asset_details)
        self.ui.assetTable.doubleClicked.connect(self._open_asset_details)
        self._update_counts()
        self._update_asset_counts()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        self.ui.reconPages = QTabWidget()
        root.addWidget(self.ui.reconPages)
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

        tools = QGroupBox("Tool Manager · future integration")
        tools_layout = QVBoxLayout(tools)
        tools_layout.setSpacing(2)
        for name in ("Subfinder", "ProjectDiscovery httpx", "Nmap", "FFUF"):
            tools_layout.addWidget(QLabel(f"{name} — Unavailable / not connected"))
        layout.addWidget(tools)
        self._build_asset_inventory()

    def _build_asset_inventory(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(8)
        title = QLabel("Recon · Asset Inventory")
        title.setStyleSheet("font-size: 22px; font-weight: 600;")
        layout.addWidget(title)
        note = QLabel(
            "Offline observations from local JSON files. Assets remain separate from imported targets; "
            "scope is unreviewed and selection does not authorize active scanning."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        actions = QHBoxLayout()
        self.ui.btnImportObservations = QPushButton("Import Observations JSON…")
        self.ui.btnAssetDetails = QPushButton("Details")
        self.ui.btnAssetDetails.setEnabled(False)
        actions.addWidget(self.ui.btnImportObservations)
        actions.addWidget(self.ui.btnAssetDetails)
        actions.addStretch(1)
        self.ui.assetCountLabel = QLabel()
        actions.addWidget(self.ui.assetCountLabel)
        layout.addLayout(actions)

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
        self._clear_asset_selection()
        self.asset_model.set_assets(self.asset_inventory.assets)
        self._refresh_asset_sources()
        self._update_asset_counts()
        self.ui.assetStatusLabel.setText(
            f"Added: {result.added_observations} · Duplicates: {result.duplicates} · "
            f"Assets: {result.total_assets}"
        )
        return True

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
        self._update_asset_counts()

    def _clear_asset_selection(self):
        self.ui.assetTable.clearSelection()
        self.ui.assetTable.setCurrentIndex(QModelIndex())
        self._update_asset_details_button()

    def _update_asset_counts(self):
        self.ui.assetCountLabel.setText(
            f"Total: {self.asset_model.rowCount()} · Filtered: {self.asset_proxy.rowCount()}"
        )

    def _update_asset_details_button(self, *_args):
        self.ui.btnAssetDetails.setEnabled(bool(self.ui.assetTable.selectionModel().selectedRows()))

    def _open_asset_details(self, index=None):
        if not isinstance(index, QModelIndex) or not index.isValid():
            selected = self.ui.assetTable.selectionModel().selectedRows()
            if not selected:
                return
            index = selected[0]
        source_index = self.asset_proxy.mapToSource(index)
        asset = self.asset_model.asset_at(source_index.row()) if source_index.isValid() else None
        if asset is None:
            return
        UniversalViewerDialog(
            title=f"Recon asset: {asset.value}", payload=asset.to_dict(), parent=self,
            show_summary=False, default_save_stem="recon_asset",
        ).exec()

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
        self.ui.issueTable.setVisible(bool(report.issues))
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
            self.ui.issueTable.hide()
            self.ui.importSummary.setText("Added: 0 · Duplicates: 0 · Invalid: 0")
            self.ui.statusLabel.setText("Target list cleared.")
