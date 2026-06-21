from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, parse_qsl, urljoin, urlparse

from PySide6.QtCore import Qt, QUrl, QSignalBlocker
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QMessageBox,
    QSplitter,
    QTableWidgetItem,
    QHeaderView,
    QTableWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.metadata import AnnotationStore, build_discovery_url_entity_key
from dialogs.results_viewer_dialog import UniversalViewerDialog


DISCOVERY_URL_ENTITY_KEY_ROLE = Qt.UserRole + 2


def _project_root() -> Path:
    markers = ("main.py", "pyproject.toml", "requirements.txt", ".git")
    module_dir = Path(__file__).resolve().parent
    for candidate in (module_dir, *module_dir.parents):
        if any((candidate / marker).exists() for marker in markers):
            return candidate
    return Path.cwd()


def _discovery_export_dir() -> Path:
    export_dir = _project_root() / "data" / "Discovery_Urls"
    export_dir.mkdir(parents=True, exist_ok=True)
    return export_dir


class DiscoveryViewerDialog(QDialog):
    _GROUP_LABELS = {
        "internal": "Internal URLs",
        "external": "External URLs",
        "forms": "Forms",
        "params": "Query Params",
        "high_value": "High-value endpoints",
    }
    _DISCOVERY_FILTERS = (
        "All",
        "Internal only",
        "External only",
        "With params only",
        "Forms only",
        "Auth/Admin/API/Upload only",
        "High-value only",
    )
    _AUTH_ADMIN_API_UPLOAD_KEYWORDS = ("auth", "login", "admin", "api", "upload")
    _HIGH_VALUE_KEYWORDS = (
        "admin", "login", "auth", "api", "upload", "file", "download",
        "redirect", "callback", "token", "reset", "password", "user",
        "account", "config", "debug",
    )

    def __init__(
        self,
        discovery: dict,
        parent=None,
        add_task_callback: Optional[Callable[[List[str]], Any]] = None,
        task_id=None,
        annotation_store: Optional[AnnotationStore] = None,
    ):
        super().__init__(parent)
        self.discovery = discovery if isinstance(discovery, dict) else {}
        self._add_task_callback = add_task_callback
        self.task_id = task_id
        self.annotation_store = annotation_store
        self._rows_cache: Dict[str, List[Dict[str, Any]]] = {
            "internal": [], "external": [], "params": [], "high_value": [],
        }
        self._selected_url: Optional[str] = None
        self._current_details_key: Optional[str] = None
        self._details_widgets: Dict[str, Dict[str, Any]] = {}
        self._forms_cache: List[Any] = []
        self._query_params_cache: List[tuple[str, str]] = []
        self._row_payloads: Dict[int, Any] = {}

        self.setWindowTitle("Discovery Viewer")
        self.setMinimumSize(1000, 650)
        self.setSizeGripEnabled(True)
        self.setWindowState(self.windowState() | Qt.WindowMaximized)

        main_layout = QVBoxLayout(self)

        # Top controls: search + filters + counters
        top_bar = QHBoxLayout()
        self.search_edit = QLineEdit(self)
        self.search_edit.setPlaceholderText("Search URL / host / path / param...")
        self.filter_label = QLabel("Filter:", self)
        self.discovery_filter = QComboBox(self)
        self.discovery_filter.addItems(self._DISCOVERY_FILTERS)
        self.export_view_button = QPushButton("Export View", self)
        self.cb_only_params = QCheckBox("Only with params", self)
        self.cb_hide_duplicates = QCheckBox("Hide duplicates", self)
        self.counters_label = QLabel("Internal: 0 | External: 0 | With params: 0 | Total: 0", self)
        self.counters_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        top_bar.addWidget(self.search_edit, stretch=2)
        top_bar.addWidget(self.filter_label)
        top_bar.addWidget(self.discovery_filter)
        top_bar.addWidget(self.export_view_button)
        top_bar.addWidget(self.cb_only_params)
        top_bar.addWidget(self.cb_hide_duplicates)
        top_bar.addWidget(self.counters_label, stretch=1)
        main_layout.addLayout(top_bar)

        # Tabs
        self.tabs = QTabWidget(self)
        self.tabs.addTab(self._build_tab("table_internal"), "Internal URLs (0)")
        self.tabs.addTab(self._build_tab("table_external"), "External URLs (0)")
        self.forms_text = self._build_text_tab("forms")
        self.tabs.addTab(self.forms_text.parentWidget(), "Forms (0)")
        self.query_params_text = self._build_text_tab("params")
        self.tabs.addTab(self.query_params_text.parentWidget(), "Query Params (0)")
        self.tabs.addTab(self._build_tab("table_high_value"), "High-value endpoints (0)")
        main_layout.addWidget(self.tabs, stretch=1)
        self.empty_filter_label = QLabel("No items for selected filter", self)
        self.empty_filter_label.setAlignment(Qt.AlignCenter)
        self.empty_filter_label.hide()
        main_layout.addWidget(self.empty_filter_label)

        self._setup_tables()
        initial_rows = self._extract_rows()
        self._populate_tables(initial_rows)
        self._rebuild_cache()
        self._populate_summary_groups()
        self._refresh_view()

        # Bottom buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Close, parent=self)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        main_layout.addWidget(buttons)

        # Filters
        self.search_edit.textChanged.connect(self._refresh_view)
        self.discovery_filter.currentTextChanged.connect(self._refresh_view)
        self.cb_only_params.stateChanged.connect(self._refresh_view)
        self.cb_hide_duplicates.stateChanged.connect(self._refresh_view)
        self.export_view_button.clicked.connect(self._export_filtered_view)
        self.table_internal.itemSelectionChanged.connect(lambda: self._on_selection_changed("internal"))
        self.table_external.itemSelectionChanged.connect(lambda: self._on_selection_changed("external"))
        self.table_high_value.itemSelectionChanged.connect(lambda: self._on_selection_changed("high_value"))


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

    def _build_text_tab(self, group_key: str) -> QPlainTextEdit:
        tab = QWidget(self)
        layout = QVBoxLayout(tab)
        text = QPlainTextEdit(tab)
        text.setReadOnly(True)
        text.setContextMenuPolicy(Qt.CustomContextMenu)
        text.customContextMenuRequested.connect(
            lambda pos, editor=text, key=group_key:
            self._show_discovery_text_context_menu(editor, key, pos)
        )
        layout.addWidget(text)
        return text

    def _setup_tables(self):
        columns = ["URL", "Host", "Path", "Params", "Param names"]
        tables = [
            getattr(self, "table_internal", None),
            getattr(self, "table_external", None),
            getattr(self, "table_high_value", None),
        ]
        for table in tables:
            if table is None:
                continue
            table.setColumnCount(len(columns))
            table.setHorizontalHeaderLabels(columns)
            table.setSelectionBehavior(QAbstractItemView.SelectRows)
            table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            table.setAlternatingRowColors(True)
            table.setSortingEnabled(True)
            table.setContextMenuPolicy(Qt.CustomContextMenu)
            key = table.objectName().replace("table_", "", 1)
            table.customContextMenuRequested.connect(
                lambda pos, current_table=table, group_key=key:
                self._show_discovery_context_menu(current_table, group_key, pos)
            )

            header = table.horizontalHeader()
            header.setSectionResizeMode(0, QHeaderView.Stretch)
            header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.Interactive)

    def _populate_tables(self, rows: Dict[str, List[Dict[str, Any]]]):
        internal = rows.get("internal", []) if rows else []
        external = rows.get("external", []) if rows else []
        high_value = rows.get("high_value", []) if rows else []

        self._fill_table(getattr(self, "table_internal", None), internal)
        self._fill_table(getattr(self, "table_external", None), external)
        self._fill_table(getattr(self, "table_high_value", None), high_value)

    def _refresh_view(self):
        grouped = self._current_filtered_groups()
        internal = grouped["internal"]
        external = grouped["external"]
        params = grouped["param_rows"]
        high_value = grouped["high_value"]

        self._populate_tables({
            "internal": internal,
            "external": external,
            "params": params,
            "high_value": high_value,
        })
        self._render_grouped_discovery(grouped)
        self._update_action_buttons()
        self._update_counters(grouped)

    def _current_filtered_groups(self) -> Dict[str, Any]:
        base = self._rows_cache or {"internal": [], "external": [], "params": []}
        internal = list(base.get("internal", []))
        external = list(base.get("external", []))
        params = list(base.get("params", []))
        high_value = list(base.get("high_value", []))

        if self.cb_hide_duplicates.isChecked():
            internal = self._dedupe(internal)
            external = self._dedupe(external)
            params = self._dedupe(params)
            high_value = self._dedupe(high_value)

        if self.cb_only_params.isChecked():
            internal = [r for r in internal if r.get("params_count", 0) > 0]
            external = [r for r in external if r.get("params_count", 0) > 0]
            params = [r for r in params if r.get("params_count", 0) > 0]
            high_value = [r for r in high_value if r.get("params_count", 0) > 0]

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
            high_value = [r for r in high_value if _match(r)]

        grouped = self._apply_discovery_filter({
            "internal": internal,
            "external": external,
            "high_value": high_value,
        })
        grouped["param_rows"] = params
        return grouped

    def _current_filter_label(self) -> str:
        return self.discovery_filter.currentText() or "All"

    def _export_filtered_view(self):
        try:
            default_path = _discovery_export_dir() / "discovery_filtered_view.json"
        except OSError as exc:
            QMessageBox.warning(
                self,
                "Export Failed",
                f"Could not create the Discovery Viewer export directory:\n{exc}",
            )
            return

        path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Discovery Filtered View",
            str(default_path),
            "JSON Files (*.json);;Text Files (*.txt);;All Files (*)",
        )
        if not path:
            return

        if not path.lower().endswith((".json", ".txt")):
            path += ".txt" if selected_filter.startswith("Text Files") else ".json"

        try:
            data = self._build_filtered_export_data()
            if path.lower().endswith(".txt"):
                self._write_filtered_view_text(path, data)
            else:
                self._write_filtered_view_json(path, data)
        except Exception as exc:
            QMessageBox.warning(self, "Export Failed", f"Could not export filtered view:\n{exc}")
            return

        QMessageBox.information(self, "Export Complete", "Filtered discovery view exported successfully.")

    def _build_filtered_export_data(self) -> Dict[str, Any]:
        grouped = self._current_filtered_groups()
        visible = grouped.get("visible", set())
        groups: Dict[str, List[Any]] = {}

        for key, label in self._GROUP_LABELS.items():
            if key not in visible:
                continue
            if key in ("internal", "external", "high_value"):
                items = [dict(row) for row in grouped.get(key, [])]
            elif key == "forms":
                items = [self._format_form(item, index) for index, item in enumerate(grouped.get(key, []), 1)]
            else:
                items = [
                    {"name": str(name), "example": str(example)}
                    for name, example in grouped.get(key, [])
                ]
            groups[label] = items

        return {
            "export_type": "discovery_filtered_view",
            "filter": self._current_filter_label(),
            "groups": groups,
            "counts": {label: len(items) for label, items in groups.items()},
        }

    @staticmethod
    def _write_filtered_view_json(path: str, data: Dict[str, Any]):
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)

    @classmethod
    def _write_filtered_view_text(cls, path: str, data: Dict[str, Any]):
        lines = ["Discovery Filtered View", f"Filter: {data.get('filter', 'All')}", ""]
        for label, items in data.get("groups", {}).items():
            lines.append(f"{label} ({len(items)})")
            if not items:
                lines.append("No items")
            else:
                lines.extend(f"- {cls._format_export_text_item(label, item)}" for item in items)
            lines.append("")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines).rstrip() + "\n")

    @staticmethod
    def _format_export_text_item(label: str, item: Any) -> str:
        if isinstance(item, dict):
            if label == "Query Params":
                name = item.get("name", "")
                example = item.get("example", "")
                return f"{name} (Example: {example})" if example else str(name)
            return str(item.get("url") or item)
        return str(item).replace("\n", "\n  ")

    def _apply_discovery_filter(self, rows: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        selected = self.discovery_filter.currentText() or "All"
        visible = {"internal", "external", "forms", "params", "high_value"}

        if selected == "Internal only":
            visible = {"internal"}
        elif selected == "External only":
            visible = {"external"}
        elif selected == "With params only":
            visible = {"internal", "external", "params", "high_value"}
            rows = {
                key: [row for row in rows.get(key, []) if row.get("params_count", 0) > 0]
                for key in ("internal", "external", "high_value")
            }
        elif selected == "Forms only":
            visible = {"forms"}
        elif selected == "Auth/Admin/API/Upload only":
            visible = {"internal", "external", "high_value"}
            rows = {
                key: [row for row in rows.get(key, []) if self._matches_auth_admin_api_upload(row)]
                for key in ("internal", "external", "high_value")
            }
        elif selected == "High-value only":
            visible = {"high_value"}

        return {
            "internal": list(rows.get("internal", [])) if "internal" in visible else [],
            "external": list(rows.get("external", [])) if "external" in visible else [],
            "high_value": list(rows.get("high_value", [])) if "high_value" in visible else [],
            "forms": list(self._forms_cache),
            "params": list(self._query_params_cache),
            "visible": visible,
        }

    @classmethod
    def _matches_auth_admin_api_upload(cls, row: Dict[str, Any]) -> bool:
        text = " ".join(str(row.get(key, "")) for key in ("url", "host", "path")).lower()
        return any(keyword in text for keyword in cls._AUTH_ADMIN_API_UPLOAD_KEYWORDS)

    def _render_grouped_discovery(self, grouped: Dict[str, Any]):
        visible = grouped.get("visible", set())
        tab_keys = ("internal", "external", "forms", "params", "high_value")
        for index, key in enumerate(tab_keys):
            self.tabs.setTabVisible(index, key in visible)

        visible_count = sum(len(grouped.get(key, [])) for key in visible)
        self.empty_filter_label.setVisible(visible_count == 0)

    def _update_counters(self, grouped: Dict[str, Any]):
        visible = grouped.get("visible", set())
        n_internal = len(grouped.get("internal", [])) if "internal" in visible else 0
        n_external = len(grouped.get("external", [])) if "external" in visible else 0
        n_forms = len(grouped.get("forms", [])) if "forms" in visible else 0
        n_query_params = len(grouped.get("params", [])) if "params" in visible else 0
        n_high_value = len(grouped.get("high_value", [])) if "high_value" in visible else 0

        visible_url_rows = grouped.get("internal", []) + grouped.get("external", [])
        if not visible_url_rows and "high_value" in visible:
            visible_url_rows = grouped.get("high_value", [])
        n_params = len([row for row in visible_url_rows if row.get("params_count", 0) > 0])
        total = len(visible_url_rows)
        self.counters_label.setText(f"Internal: {n_internal} | External: {n_external} | With params: {n_params} | Total: {total}")
        self.tabs.setTabText(0, f"Internal URLs ({n_internal})")
        self.tabs.setTabText(1, f"External URLs ({n_external})")
        self.tabs.setTabText(2, f"Forms ({n_forms})")
        self.tabs.setTabText(3, f"Query Params ({n_query_params})")
        self.tabs.setTabText(4, f"High-value endpoints ({n_high_value})")

    def _fill_table(self, table: QTableWidget | None, rows: List[Dict[str, Any]]):
        if table is None:
            return
        table.setSortingEnabled(False)
        table.setRowCount(0)
        if not rows:
            table.insertRow(0)
            empty_item = QTableWidgetItem("No items")
            empty_item.setFlags(empty_item.flags() & ~Qt.ItemIsSelectable)
            table.setItem(0, 0, empty_item)
            table.setSpan(0, 0, 1, table.columnCount())
            table.setSortingEnabled(True)
            return
        for row_data in rows:
            row_idx = table.rowCount()
            table.insertRow(row_idx)
            full_url = str(row_data.get("url", ""))
            display_url = full_url if len(full_url) <= 240 else full_url[:237] + "..."
            url_item = QTableWidgetItem(display_url)
            url_item.setData(Qt.UserRole, full_url)
            url_item.setData(
                Qt.UserRole + 1,
                self._row_payloads.get(id(row_data), dict(row_data)),
            )
            entity_key = self._build_discovery_url_entity_key(full_url)
            if entity_key is not None:
                url_item.setData(DISCOVERY_URL_ENTITY_KEY_ROLE, entity_key)
            if display_url != full_url:
                url_item.setToolTip(full_url)
            table.setItem(row_idx, 0, url_item)
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

    def _build_discovery_url_entity_key(self, url: str) -> Optional[str]:
        if self.task_id is None:
            return None
        try:
            return build_discovery_url_entity_key(self.task_id, url)
        except (TypeError, ValueError):
            return None

    def _rebuild_cache(self):
        self._rows_cache = self._extract_rows()

    def _on_selection_changed(self, key: str):
        tables = {
            "internal": getattr(self, "table_internal", None),
            "external": getattr(self, "table_external", None),
            "high_value": getattr(self, "table_high_value", None),
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

    def _selected_discovery_items(self, table: QTableWidget) -> List[Any]:
        selection_model = table.selectionModel()
        if not selection_model:
            return []

        payloads: List[Any] = []
        for index in selection_model.selectedRows():
            item = table.item(index.row(), 0)
            if item is None or not (item.flags() & Qt.ItemIsSelectable):
                continue
            payload = item.data(Qt.UserRole + 1)
            if payload is None:
                payload = item.data(Qt.UserRole)
            if payload is None:
                payload = item.text()
            if payload not in (None, ""):
                payloads.append(payload)
        return payloads

    def _selected_discovery_payload(self, table: QTableWidget) -> Any:
        payloads = self._selected_discovery_items(table)
        if not payloads:
            return None
        return payloads[0] if len(payloads) == 1 else payloads

    @staticmethod
    def _payload_to_clipboard_text(payload: Any) -> str:
        if isinstance(payload, dict):
            for key in ("url", "href", "endpoint", "path", "value"):
                value = payload.get(key)
                if value not in (None, ""):
                    return str(value)
            return json.dumps(payload, ensure_ascii=False, indent=2, default=str)
        if isinstance(payload, (list, tuple)):
            return json.dumps(payload, ensure_ascii=False, indent=2, default=str)
        return str(payload)

    def _copy_selected_discovery_item(self, table: QTableWidget):
        payload = self._selected_discovery_payload(table)
        if payload is None:
            return
        QApplication.clipboard().setText(self._payload_to_clipboard_text(payload))

    def _open_selected_discovery_item(self, table: QTableWidget, group_key: str):
        payload = self._selected_discovery_payload(table)
        if payload is None:
            return
        title = f"Discovery: {self._GROUP_LABELS.get(group_key, 'Item')}"
        if isinstance(payload, (dict, list, tuple)):
            dialog = UniversalViewerDialog(title=title, payload=payload, parent=self)
        else:
            dialog = UniversalViewerDialog(title=title, content=str(payload), parent=self)
        dialog.exec()

    @staticmethod
    def _absolute_http_url(value: Any, base_url: str = "") -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        try:
            parsed = urlparse(text)
            if parsed.scheme:
                if parsed.scheme.lower() not in ("http", "https"):
                    return ""
                return text if parsed.netloc else ""
            if not base_url:
                return ""
            resolved = urljoin(base_url, text)
            resolved_parsed = urlparse(resolved)
            if resolved_parsed.scheme.lower() in ("http", "https") and resolved_parsed.netloc:
                return resolved
        except (TypeError, ValueError):
            return ""
        return ""

    def _discovery_base_url(self) -> str:
        for key in ("base_url", "url", "target_url", "origin"):
            value = self._absolute_http_url(self.discovery.get(key))
            if value:
                return value
        return ""

    def _url_from_discovery_payload(self, payload: Any) -> str:
        base_url = self._discovery_base_url()
        if isinstance(payload, dict):
            for base_key in ("base_url", "origin", "source_url", "page_url"):
                payload_base = self._absolute_http_url(payload.get(base_key), base_url)
                if payload_base:
                    base_url = payload_base
                    break
            for key in ("url", "href", "endpoint", "absolute_url", "full_url", "action"):
                if payload.get(key) not in (None, ""):
                    url = self._absolute_http_url(payload.get(key), base_url)
                    if url:
                        return url
            return ""
        text = str(payload or "").strip()
        if text.lower() == "no items":
            return ""
        parsed = urlparse(text)
        if not parsed.scheme and not (
            text.startswith(("/", "./", "../"))
            or ("/" in text and not any(character.isspace() for character in text))
        ):
            return ""
        return self._absolute_http_url(text, base_url)

    def _add_selected_payloads_as_tasks(self, payloads: List[Any]):
        urls: List[str] = []
        seen = set()
        for payload in payloads:
            url = self._url_from_discovery_payload(payload)
            if url and url not in seen:
                seen.add(url)
                urls.append(url)

        if not urls:
            QMessageBox.information(
                self, "Add task", "Selected item does not contain a usable URL."
            )
            return
        if not callable(self._add_task_callback):
            QMessageBox.information(
                self, "Add task", "Adding tasks is not available from this viewer."
            )
            return

        try:
            result = self._add_task_callback(urls)
        except Exception as exc:
            QMessageBox.warning(self, "Add task", f"Could not add selected task(s): {exc}")
            return
        added_count = (
            result
            if isinstance(result, int) and not isinstance(result, bool)
            else len(urls)
        )
        QMessageBox.information(self, "Add task", f"Added {added_count} task(s).")

    def _show_discovery_context_menu(
        self,
        table: QTableWidget,
        group_key: str,
        pos,
    ):
        clicked_item = table.itemAt(pos)
        if clicked_item is not None and clicked_item.flags() & Qt.ItemIsSelectable:
            if not clicked_item.isSelected():
                table.clearSelection()
                table.selectRow(clicked_item.row())

        has_selection = bool(self._selected_discovery_items(table))
        menu = QMenu(table)
        copy_action = menu.addAction("Copy Selected")
        open_action = menu.addAction("Open Selected in Viewer")
        add_task_action = menu.addAction("Add Selected as Task")
        copy_action.setEnabled(has_selection)
        open_action.setEnabled(has_selection)
        add_task_action.setEnabled(has_selection)
        copy_action.triggered.connect(lambda: self._copy_selected_discovery_item(table))
        open_action.triggered.connect(
            lambda: self._open_selected_discovery_item(table, group_key)
        )
        add_task_action.triggered.connect(
            lambda: self._add_selected_payloads_as_tasks(
                self._selected_discovery_items(table)
            )
        )
        menu.exec(table.viewport().mapToGlobal(pos))

    @staticmethod
    def _selected_discovery_text(editor: QPlainTextEdit) -> str:
        selected = editor.textCursor().selectedText().replace("\u2029", "\n").strip()
        return "" if selected.casefold() == "no items" else selected

    def _show_discovery_text_context_menu(
        self,
        editor: QPlainTextEdit,
        group_key: str,
        pos,
    ):
        selected_text = self._selected_discovery_text(editor)
        menu = editor.createStandardContextMenu()
        menu.addSeparator()
        copy_action = menu.addAction("Copy Selected")
        open_action = menu.addAction("Open Selected in Viewer")
        add_task_action = menu.addAction("Add Selected as Task")
        copy_action.setEnabled(bool(selected_text))
        open_action.setEnabled(bool(selected_text))
        add_task_action.setEnabled(bool(selected_text))
        def _copy_selected_text():
            text = self._selected_discovery_text(editor)
            if text:
                QApplication.clipboard().setText(text)

        def _open_selected_text():
            text = self._selected_discovery_text(editor)
            if text:
                UniversalViewerDialog(
                    title=f"Discovery: {self._GROUP_LABELS.get(group_key, 'Item')}",
                    content=text,
                    parent=self,
                ).exec()

        copy_action.triggered.connect(_copy_selected_text)
        open_action.triggered.connect(_open_selected_text)
        add_task_action.triggered.connect(
            lambda: self._add_selected_payloads_as_tasks(
                [self._selected_discovery_text(editor)]
            )
        )
        menu.exec(editor.viewport().mapToGlobal(pos))

    def _extract_rows(self) -> Dict[str, List[Dict[str, Any]]]:
        """Build rows for internal/external/params views from self.discovery."""
        empty = {"internal": [], "external": [], "params": []}
        if not self.discovery or not isinstance(self.discovery, dict):
            return empty

        urls_section = self.discovery.get("urls")
        if not isinstance(urls_section, dict):
            urls_section = {}

        internal_urls = self._safe_list(urls_section.get("internal"))
        external_urls = self._safe_list(urls_section.get("external"))

        if not internal_urls and not external_urls:
            flat_urls = self._safe_list(urls_section.get("all"))
            if not flat_urls:
                for key in ("urls", "links", "endpoints", "internal_urls"):
                    flat_urls.extend(self._safe_list(self.discovery.get(key)))
            external_urls.extend(self._safe_list(self.discovery.get("external_urls")))
            base_host = self._url_host(self.discovery.get("base_url"))
            for item in flat_urls:
                item_host = self._url_host(item)
                if base_host and item_host and item_host != base_host:
                    external_urls.append(item)
                else:
                    internal_urls.append(item)

        rows_internal = self._build_rows_with_payloads(internal_urls)
        rows_external = self._build_rows_with_payloads(external_urls)

        rows_internal = self._dedupe(rows_internal)
        rows_external = self._dedupe(rows_external)

        rows_params_source = rows_internal + rows_external
        rows_params = [r for r in rows_params_source if r.get("params_count", 0) > 0]
        rows_params = self._dedupe(rows_params)
        rows_high_value = [
            row for row in rows_params_source
            if self._is_high_value_endpoint(row.get("url"))
        ]

        return {
            "internal": rows_internal,
            "external": rows_external,
            "params": rows_params,
            "high_value": self._dedupe(rows_high_value),
        }

    def _build_rows_with_payloads(self, values: List[Any]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for value in values:
            row = self._build_row(value)
            if row:
                self._row_payloads[id(row)] = value
                rows.append(row)
        return rows

    @staticmethod
    def _safe_list(value: Any) -> List[Any]:
        if isinstance(value, (list, tuple, set)):
            return [item for item in value if item not in (None, "")]
        if isinstance(value, str) and value.strip():
            return [value]
        return []

    @staticmethod
    def _url_host(value: Any) -> str:
        try:
            return (urlparse(str(value or "")).hostname or "").lower()
        except Exception:
            return ""

    def _is_high_value_endpoint(self, value: Any) -> bool:
        text = str(value or "").lower()
        return any(keyword in text for keyword in self._HIGH_VALUE_KEYWORDS)

    def _populate_summary_groups(self):
        forms_value = self.discovery.get("forms")
        if forms_value is None:
            forms_value = self.discovery.get("form_entries", self.discovery.get("form"))
        if isinstance(forms_value, dict):
            nested_forms = forms_value.get("forms") or forms_value.get("items")
            forms = self._safe_list(nested_forms) if nested_forms is not None else [forms_value]
        else:
            forms = self._safe_list(forms_value)
        self._forms_cache = forms
        form_lines = [self._format_form(item, index) for index, item in enumerate(forms, 1)]
        self.forms_text.setPlainText("\n\n".join(form_lines) if form_lines else "No items")

        params = self._extract_query_param_examples()
        self._query_params_cache = params
        param_lines = [
            f"{name}\n  Example: {example}" if example else name
            for name, example in params
        ]
        self.query_params_text.setPlainText("\n\n".join(param_lines) if param_lines else "No items")
        self.tabs.setTabText(2, f"Forms ({len(forms)})")
        self.tabs.setTabText(3, f"Query Params ({len(params)})")

    def _format_form(self, form: Any, index: int) -> str:
        if not isinstance(form, dict):
            return str(form)
        action = form.get("action") or form.get("url") or "(no action)"
        method = str(form.get("method") or "GET").upper()
        inputs = form.get("input_names") or form.get("inputs") or form.get("params") or []
        if isinstance(inputs, dict):
            input_names = [str(name) for name in inputs.keys()]
        elif isinstance(inputs, (list, tuple, set)):
            input_names = [
                str(item.get("name") or "") if isinstance(item, dict) else str(item)
                for item in inputs
            ]
        else:
            input_names = [str(inputs)] if inputs else []
        names = ", ".join(name for name in input_names if name) or "No inputs"
        return f"{index}. {method} {action}\n   Inputs: {names}"

    def _extract_query_param_examples(self) -> List[tuple[str, str]]:
        examples: Dict[str, str] = {}
        existing = self.discovery.get("query_params")
        if existing is None:
            existing = self.discovery.get("query_parameters", self.discovery.get("parameters"))
        if isinstance(existing, dict):
            for source, values in existing.items():
                if isinstance(values, dict):
                    for name, value in values.items():
                        example = f"{source} ({value})" if value not in (None, "") else str(source)
                        examples.setdefault(str(name), example)
                elif isinstance(values, (list, tuple, set)):
                    for name in values:
                        examples.setdefault(str(name), str(source))
                elif values not in (None, ""):
                    examples.setdefault(str(source), str(values))
        elif isinstance(existing, (list, tuple, set)):
            for item in existing:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("param") or item.get("key")
                    if name:
                        examples.setdefault(str(name), str(item.get("example") or item.get("url") or ""))
                elif item not in (None, ""):
                    examples.setdefault(str(item), "")

        for row in self._rows_cache.get("internal", []) + self._rows_cache.get("external", []):
            url = str(row.get("url") or "")
            try:
                pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
            except Exception:
                pairs = []
            for name, value in pairs:
                examples.setdefault(name, f"{url} ({value})" if value else url)
        return sorted(examples.items(), key=lambda item: item[0].lower())

    def _build_row(self, full_url: Any) -> Dict[str, Any] | None:
        if not full_url:
            return None
        url_value = full_url
        if isinstance(full_url, dict):
            for key in ("url", "href", "absolute_url", "full_url", "endpoint", "path", "action", "value"):
                value = full_url.get(key)
                if value not in (None, ""):
                    url_value = value
                    break
        try:
            parsed = urlparse(str(url_value))
        except Exception:
            return None

        param_keys = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True)})
        param_names_full = ",".join(param_keys)
        host = parsed.hostname or ""
        path = parsed.path or "/"

        if isinstance(full_url, dict):
            host = str(full_url.get("host") or host)
            path = str(full_url.get("path") or path)
            existing_names = full_url.get("param_names_full", full_url.get("param_names"))
            if existing_names not in (None, ""):
                param_names_full = str(existing_names)
            elif isinstance(full_url.get("params"), dict):
                param_names_full = ",".join(str(name) for name in full_url["params"])
            elif isinstance(full_url.get("params"), (list, tuple, set)):
                param_names_full = ",".join(
                    str(item.get("name") or "") if isinstance(item, dict) else str(item)
                    for item in full_url["params"]
                )

        params_count = len(param_keys)
        if isinstance(full_url, dict) and full_url.get("params_count") is not None:
            params_count = full_url.get("params_count")
        elif param_names_full:
            params_count = len([name for name in param_names_full.split(",") if name])

        return {
            "url": str(url_value),
            "host": host,
            "path": path,
            "params_count": params_count,
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
        return str(item.data(Qt.UserRole) or item.text()) if item else ""

    def _set_actions_enabled(self, enabled: bool, key: Optional[str] = None):
        for k, widgets in self._details_widgets.items():
            active = enabled and k == key
            if widgets.get("btn_copy"):
                widgets["btn_copy"].setEnabled(active)
            if widgets.get("btn_open"):
                widgets["btn_open"].setEnabled(active)
