"""Passive NSE catalog browser; selection is configuration, never execution."""

from types import SimpleNamespace

from PySide6.QtCore import QSignalBlocker, Qt, Signal
from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)


class NmapScriptCatalogWidget(QWidget):
    selectionChanged = Signal(tuple)

    def __init__(self, parent=None, *, catalog_loader=None):
        super().__init__(parent)
        self._loader = catalog_loader
        self._catalog = ()
        self._selected = ()
        self.ui = SimpleNamespace()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.ui.load = QPushButton("Load verified script catalog")
        self.ui.load.setToolTip("Read scripts from the explicitly verified Nmap installation. Executes nothing.")
        layout.addWidget(self.ui.load)
        filters = QHBoxLayout()
        self.ui.search = QLineEdit()
        self.ui.search.setPlaceholderText("Search scripts or descriptions")
        self.ui.category = QComboBox()
        self.ui.category.addItem("All categories", None)
        filters.addWidget(self.ui.search, 1)
        filters.addWidget(self.ui.category)
        layout.addLayout(filters)
        self.ui.scripts = QListWidget()
        self.ui.scripts.setMinimumHeight(130)
        layout.addWidget(self.ui.scripts)
        self.ui.details = QPlainTextEdit()
        self.ui.details.setReadOnly(True)
        self.ui.details.setMaximumHeight(115)
        layout.addWidget(self.ui.details)
        self.ui.status = QLabel("Verify Nmap, then explicitly load its local script catalog. No scripts run automatically.")
        self.ui.status.setTextFormat(Qt.PlainText)
        self.ui.status.setWordWrap(True)
        layout.addWidget(self.ui.status)
        self.ui.load.clicked.connect(self._load)
        self.ui.search.textChanged.connect(self._filter)
        self.ui.category.currentIndexChanged.connect(self._filter)
        self.ui.scripts.itemChanged.connect(self._check_changed)
        self.ui.scripts.currentItemChanged.connect(self._details)

    def selected_ids(self):
        return self._selected

    def set_selected(self, script_ids):
        self._selected = tuple(sorted(set(script_ids)))
        self._filter()

    def _load(self):
        try:
            if self._loader is None:
                raise ValueError("Choose and verify Nmap in Recon Tool Inspector first.")
            catalog = tuple(self._loader())
        except (ValueError, OSError, RuntimeError) as error:
            self.ui.status.setText(f"Catalog unavailable: {error}")
            return
        self._catalog = catalog
        with QSignalBlocker(self.ui.category):
            self.ui.category.clear()
            self.ui.category.addItem("All categories", None)
            for category in sorted({category for item in catalog for category in item.categories}):
                self.ui.category.addItem(category, category)
        self.ui.status.setText(f"{len(catalog)} installed scripts. Selection needs per-run approval; high impact needs extra confirmation.")
        self._filter()

    def _filter(self, *_args):
        search = self.ui.search.text().strip().casefold()
        category = self.ui.category.currentData()
        with QSignalBlocker(self.ui.scripts):
            self.ui.scripts.clear()
            for script in self._catalog:
                if category and category not in script.categories:
                    continue
                if search and search not in (script.script_id + " " + script.description).casefold():
                    continue
                item = QListWidgetItem(script.script_id)
                item.setData(Qt.UserRole, script)
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                if not getattr(script, "supported", True):
                    item.setFlags(item.flags() & ~Qt.ItemIsUserCheckable)
                    item.setToolTip(getattr(script, "unsupported_reason", "Unsupported by the scope policy."))
                item.setCheckState(Qt.Checked if script.script_id in self._selected else Qt.Unchecked)
                self.ui.scripts.addItem(item)

    def _check_changed(self, item):
        selected = set(self._selected)
        identity = item.data(Qt.UserRole).script_id
        if item.checkState() == Qt.Checked:
            selected.add(identity)
        else:
            selected.discard(identity)
        self._selected = tuple(sorted(selected))
        self.selectionChanged.emit(self._selected)

    def _details(self, item, *_args):
        if item is None:
            self.ui.details.clear()
            return
        script = item.data(Qt.UserRole)
        risky = set(script.categories) & {"intrusive", "brute", "exploit", "dos", "fuzzer", "external"}
        risk = "HIGH IMPACT: may disrupt services, attempt credentials or contact third parties." if risky else (
            "Active script probes may change service behavior. Review the script and authorized scope."
        )
        if not getattr(script, "supported", True):
            risk = "UNSUPPORTED: " + getattr(script, "unsupported_reason", "Not reviewed for exact target scope.") + "\n" + risk
        self.ui.details.setPlainText(
            f"{script.script_id}\nCategories: {', '.join(script.categories)}\n{risk}\n"
            f"{script.description}\nSHA-256: {script.sha256}"
        )
