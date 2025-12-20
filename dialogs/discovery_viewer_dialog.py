from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from PySide6.QtCore import Qt, QUrl, QSignalBlocker
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidgetItem,
    QHeaderView,
    QTableWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


class DiscoveryViewerDialog(QDialog):
    def __init__(self, discovery: dict, parent=None):
        super().__init__(parent)
        self.discovery = discovery
        self._rows_cache: Dict[str, List[Dict[str, Any]]] = {"internal": [], "external": [], "params": []}
        self._selected_url: Optional[str] = None
        self._current_details_key: Optional[str] = None
        self._details_widgets: Dict[str, Dict[str, Any]] = {}

        self.setWindowTitle("Discovery Viewer")
        self.setMinimumSize(1000, 650)

        main_layout = QVBoxLayout(self)

        # Top controls: search + filters + counters
        top_bar = QHBoxLayout()
        self.search_edit = QLineEdit(self)
        self.search_edit.setPlaceholderText("Search URL / host / path / param...")
        self.cb_only_params = QCheckBox("Only with params", self)
        self.cb_hide_duplicates = QCheckBox("Hide duplicates", self)
        self.counters_label = QLabel("Internal: 0 | External: 0 | With params: 0 | Total: 0", self)
        self.counters_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        top_bar.addWidget(self.search_edit, stretch=2)
        top_bar.addWidget(self.cb_only_params)
        top_bar.addWidget(self.cb_hide_duplicates)
        top_bar.addWidget(self.counters_label, stretch=1)
        main_layout.addLayout(top_bar)

        # Tabs
        self.tabs = QTabWidget(self)
        self.tabs.addTab(self._build_tab("table_internal"), "Internal")
        self.tabs.addTab(self._build_tab("table_external"), "External")
        self.tabs.addTab(self._build_tab("table_params"), "With params")
        main_layout.addWidget(self.tabs, stretch=1)

        self._setup_tables()
        initial_rows = self._extract_rows()
        self._populate_tables(initial_rows)
        self._rebuild_cache()
        self._refresh_view()

        # Bottom buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Close, parent=self)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        main_layout.addWidget(buttons)

        # Filters
        self.search_edit.textChanged.connect(self._refresh_view)
        self.cb_only_params.stateChanged.connect(self._refresh_view)
        self.cb_hide_duplicates.stateChanged.connect(self._refresh_view)
        self.table_internal.itemSelectionChanged.connect(lambda: self._on_selection_changed("internal"))
        self.table_external.itemSelectionChanged.connect(lambda: self._on_selection_changed("external"))
        self.table_params.itemSelectionChanged.connect(lambda: self._on_selection_changed("params"))


    def _build_tab(self, table_object_name: str) -> QWidget:
        tab = QWidget(self)
        layout = QVBoxLayout(tab)
        splitter = QSplitter(Qt.Horizontal, tab)

        table = QTableWidget(splitter)
        table.setObjectName(table_object_name)
        setattr(self, table_object_name, table)

        details_panel = QWidget(splitter)
        details_layout = QVBoxLayout(details_panel)
        details_text = QPlainTextEdit(details_panel)
        details_text.setReadOnly(True)

        buttons_layout = QHBoxLayout()
        btn_copy_url = QPushButton("Copy URL", details_panel)
        btn_open_browser = QPushButton("Open in browser", details_panel)
        btn_copy_url.clicked.connect(self._on_copy_url)
        btn_open_browser.clicked.connect(self._on_open_browser)
        buttons_layout.addWidget(btn_copy_url)
        buttons_layout.addWidget(btn_open_browser)
        buttons_layout.addStretch(1)

        details_layout.addWidget(details_text)
        details_layout.addLayout(buttons_layout)

        splitter.addWidget(table)
        splitter.addWidget(details_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)
        key = table_object_name.replace("table_", "", 1)
        self._details_widgets[key] = {
            "details_text": details_text,
            "btn_copy": btn_copy_url,
            "btn_open": btn_open_browser,
        }
        return tab

    def _setup_tables(self):
        columns = ["URL", "Host", "Path", "Params", "Param names"]
        tables = [getattr(self, "table_internal", None), getattr(self, "table_external", None), getattr(self, "table_params", None)]
        for table in tables:
            if table is None:
                continue
            table.setColumnCount(len(columns))
            table.setHorizontalHeaderLabels(columns)
            table.setSelectionBehavior(QAbstractItemView.SelectRows)
            table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            table.setAlternatingRowColors(True)
            table.setSortingEnabled(True)

            header = table.horizontalHeader()
            header.setSectionResizeMode(0, QHeaderView.Stretch)
            header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.Interactive)

    def _populate_tables(self, rows: Dict[str, List[Dict[str, Any]]]):
        internal = rows.get("internal", []) if rows else []
        external = rows.get("external", []) if rows else []
        params = rows.get("params", []) if rows else []

        self._fill_table(getattr(self, "table_internal", None), internal)
        self._fill_table(getattr(self, "table_external", None), external)
        self._fill_table(getattr(self, "table_params", None), params)

    def _refresh_view(self):
        base = self._rows_cache or {"internal": [], "external": [], "params": []}
        internal = list(base.get("internal", []))
        external = list(base.get("external", []))
        params = list(base.get("params", []))

        if self.cb_hide_duplicates.isChecked():
            internal = self._dedupe(internal)
            external = self._dedupe(external)
            params = self._dedupe(params)

        if self.cb_only_params.isChecked():
            internal = [r for r in internal if r.get("params_count", 0) > 0]
            external = [r for r in external if r.get("params_count", 0) > 0]
            params = [r for r in params if r.get("params_count", 0) > 0]

        needle = (self.search_edit.text() or "").strip().lower()
        if needle:
            def _match(row: Dict[str, Any]) -> bool:
                return any(
                    needle in str(row.get(key, "")).lower()
                    for key in ("url", "host", "path", "param_names")
                )

            internal = [r for r in internal if _match(r)]
            external = [r for r in external if _match(r)]
            params = [r for r in params if _match(r)]

        self._populate_tables({
            "internal": internal,
            "external": external,
            "params": params,
        })
        self._update_action_buttons()
        self._update_counters(internal, external, params)

    def _update_counters(self, internal: List[Dict[str, Any]], external: List[Dict[str, Any]], params: List[Dict[str, Any]]):
        n_internal = len(internal)
        n_external = len(external)
        n_params = len(params)
        total = n_internal + n_external
        self.counters_label.setText(f"Internal: {n_internal} | External: {n_external} | With params: {n_params} | Total: {total}")

    def _fill_table(self, table: QTableWidget | None, rows: List[Dict[str, Any]]):
        if table is None:
            return
        table.setSortingEnabled(False)
        table.setRowCount(0)
        for row_data in rows:
            row_idx = table.rowCount()
            table.insertRow(row_idx)
            table.setItem(row_idx, 0, QTableWidgetItem(str(row_data.get("url", ""))))
            table.setItem(row_idx, 1, QTableWidgetItem(str(row_data.get("host", ""))))
            table.setItem(row_idx, 2, QTableWidgetItem(str(row_data.get("path", ""))))
            table.setItem(row_idx, 3, QTableWidgetItem(str(row_data.get("params_count", ""))))
            full_names = str(row_data.get("param_names_full", row_data.get("param_names", "")) or "")
            display_names = full_names
            tooltip = ""
            if len(full_names) > 80:
                display_names = full_names[:77] + "…"
                tooltip = full_names
            item_names = QTableWidgetItem(display_names)
            if tooltip:
                item_names.setToolTip(tooltip)
            table.setItem(row_idx, 4, item_names)

        for col in range(1, 5):
            table.resizeColumnToContents(col)
        table.setSortingEnabled(True)

    def _rebuild_cache(self):
        self._rows_cache = self._extract_rows()

    def _on_selection_changed(self, key: str):
        tables = {
            "internal": getattr(self, "table_internal", None),
            "external": getattr(self, "table_external", None),
            "params": getattr(self, "table_params", None),
        }
        current_table = tables.get(key)
        if current_table is None:
            return

        for other_key, table in tables.items():
            if other_key == key or table is None:
                continue
            blocker = QSignalBlocker(table)
            table.clearSelection()
            self._clear_details(other_key)

        selection = current_table.selectionModel().selectedRows() if current_table.selectionModel() else []
        if not selection:
            self._selected_url = None
            self._current_details_key = None
            self._clear_details(key)
            self._update_action_buttons()
            return

        row_idx = selection[0].row()
        url = self._get_selected_url(current_table)
        host_item = current_table.item(row_idx, 1)
        path_item = current_table.item(row_idx, 2)

        host = host_item.text() if host_item else ""
        path = path_item.text() if path_item else ""

        self._selected_url = url or None
        self._current_details_key = key

        try:
            parsed = urlparse(url)
        except Exception:
            parsed = None

        params = parse_qs(parsed.query) if parsed else {}
        lines = [
            f"URL: {url}",
            f"Host: {host}",
            f"Path: {path or '/'}",
            f"Params ({len(params)}):",
        ]
        for p_key in sorted(params.keys()):
            values = params.get(p_key) or []
            if values:
                lines.append(f"- {p_key} = {','.join(values)}")
            else:
                lines.append(f"- {p_key}")

        self._set_details_text(key, "\n".join(lines).strip())
        self._update_action_buttons()

    def _set_details_text(self, key: str, text: str):
        details = self._details_widgets.get(key)
        if not details:
            return
        details_text = details.get("details_text")
        if details_text:
            details_text.setPlainText(text)

    def _clear_details(self, key: str):
        self._set_details_text(key, "")
        widgets = self._details_widgets.get(key)
        if not widgets:
            return
        self._set_actions_enabled(False, key)

    def _update_action_buttons(self):
        enabled = self._selected_url is not None
        self._set_actions_enabled(enabled, self._current_details_key)

    def _on_copy_url(self):
        if not self._selected_url:
            return
        QApplication.clipboard().setText(self._selected_url)

    def _on_open_browser(self):
        if not self._selected_url:
            return
        QDesktopServices.openUrl(QUrl(self._selected_url))

    def _extract_rows(self) -> Dict[str, List[Dict[str, Any]]]:
        """Build rows for internal/external/params views from self.discovery."""
        empty = {"internal": [], "external": [], "params": []}
        if not self.discovery or not isinstance(self.discovery, dict):
            return empty

        urls_section = self.discovery.get("urls")
        if not isinstance(urls_section, dict):
            urls_section = {}

        internal_urls = urls_section.get("internal") if isinstance(urls_section.get("internal"), list) else []
        external_urls = urls_section.get("external") if isinstance(urls_section.get("external"), list) else []

        rows_internal = [r for r in (self._build_row(u) for u in internal_urls) if r]
        rows_external = [r for r in (self._build_row(u) for u in external_urls) if r]

        rows_internal = self._dedupe(rows_internal)
        rows_external = self._dedupe(rows_external)

        rows_params_source = rows_internal + rows_external
        rows_params = [r for r in rows_params_source if r.get("params_count", 0) > 0]
        rows_params = self._dedupe(rows_params)

        return {
            "internal": rows_internal,
            "external": rows_external,
            "params": rows_params,
        }

    def _build_row(self, full_url: Any) -> Dict[str, Any] | None:
        if not full_url:
            return None
        try:
            parsed = urlparse(str(full_url))
        except Exception:
            return None

        param_keys = sorted(parse_qs(parsed.query).keys())
        param_names_full = ",".join(param_keys)

        path = parsed.path or "/"

        return {
            "url": str(full_url),
            "host": parsed.hostname or "",
            "path": path,
            "params_count": len(param_keys),
            "param_names": param_names_full,
            "param_names_full": param_names_full,
        }

    def _dedupe(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique_rows: List[Dict[str, Any]] = []
        for row in rows:
            url = row.get("url")
            if url in seen:
                continue
            seen.add(url)
            unique_rows.append(row)
        return unique_rows

    def _get_selected_url(self, table: QTableWidget | None) -> str:
        if table is None or not table.selectionModel():
            return ""
        selected = table.selectionModel().selectedRows()
        if not selected:
            return ""
        row_idx = selected[0].row()
        item = table.item(row_idx, 0)
        return item.text() if item else ""

    def _set_actions_enabled(self, enabled: bool, key: Optional[str] = None):
        for k, widgets in self._details_widgets.items():
            active = enabled and k == key
            if widgets.get("btn_copy"):
                widgets["btn_copy"].setEnabled(active)
            if widgets.get("btn_open"):
                widgets["btn_open"].setEnabled(active)
