"""Offline target entry only; no scanner, task manager, or asset inventory wiring."""

from types import SimpleNamespace

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QFileDialog, QGroupBox, QHBoxLayout, QHeaderView,
    QInputDialog, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton,
    QTableView, QVBoxLayout, QWidget,
)

from core.recon.targets import (
    ImportIssue, ImportReport, TargetRecord, csv_columns, normalize_hostname,
    parse_text, read_target_file, read_target_text,
)
from ui.recon_target_model import ImportIssueModel, ReconTargetModel


class ReconTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = SimpleNamespace()
        self.target_model = ReconTargetModel(self)
        self.issue_model = ImportIssueModel(self)
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
        self._update_counts()

    def _build_ui(self):
        layout = QVBoxLayout(self)
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
