# dialogs/data_preview_dialog.py
from __future__ import annotations
import json, os
from copy import deepcopy
from ui import export_bridge as xb
from typing import Callable
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QTableWidgetItem,
    QFileDialog,
    QMessageBox,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QComboBox,
    QMenu,
    QSizePolicy,
    QHeaderView,
)
from PySide6.QtCore import Qt, Slot, QDateTime, Signal
from dialogs.results_viewer_dialog import UniversalViewerDialog

from dialogs.ui.data_preview_dialog_ui import Ui_DataPreviewDialog  # сгенерённый класс


class DataPreviewDialog(QDialog):
    export_done = Signal(str, int)
    export_failed = Signal(str)
    PRESET_ALL_COLUMNS = "All columns"
    CORE_IDENTITY_COLUMNS = (
        "task_id",
        "url",
        "final_url",
        "status_code",
        "title",
    )
    COLUMN_PRESETS = {
        PRESET_ALL_COLUMNS: (),
        "Core Recon": (
            "task_id",
            "url",
            "final_url",
            "status_code",
            "title",
            "content_len",
            "request_ms",
            "redirects",
            "endpoint_type",
            "forms_summary",
        ),
        "Discovery Focus": (
            "discovery",
            "endpoint",
            "forms",
            "parameter",
            "redirect",
            "request_",
            "response_",
        ),
        "JS Recon": (
            "js_recon",
            "secret_hints",
            "endpoint_candidates",
            "endpoint_linkage",
        ),
        "Candidate Review": (
            "candidates",
            "findings",
            "replay",
            "artifact",
        ),
        "Fingerprint / CVE": (
            "fingerprint",
            "technology",
            "tech",
            "cve",
            "server",
            "response_content_type",
            "response_status_code",
        ),
        "Validation": (
            "validation_plan",
            "validator_queue",
            "validator_handoff",
            "replay_manifest",
        ),
    }

    def __init__(self, parent=None,
                 fetch_all: Callable[[], list[dict]] | None = None,
                 fetch_selected: Callable[[], list[dict]] | None = None ):
        super().__init__(parent)
        self.ui = Ui_DataPreviewDialog()
        self.ui.setupUi(self)
        self.setWindowTitle("Data Preview - Task Results")
        self._setup_layout()
        self._configure_table()
        
          

        self.fetch_all = fetch_all
        self.fetch_selected = fetch_selected
        self._records: list[dict] = []
        self._columns: list[str] = []
        self._column_widths_by_name: dict[str, int] = {}
        self._column_order_by_name: list[str] = []

        # signals
        self.ui.btnLoadAll.clicked.connect(self.on_load_all)
        self.ui.btnLoadSelected.clicked.connect(self.on_load_selected)
        self.ui.btnRefresh.clicked.connect(self.on_refresh)
        self.ui.btnExport.clicked.connect(self.on_export_clicked)
        self.btnResetLayout.clicked.connect(self._reset_column_layout)
        self.ui.lineSearch.textChanged.connect(self.on_filter_changed)
        self.lineColumnSearch.textChanged.connect(self._apply_column_filter)
        self.comboColumnPreset.currentTextChanged.connect(
            lambda _preset: self._apply_column_visibility_filters()
        )
        self.ui.tablePreview.cellDoubleClicked.connect(self.on_cell_dbl_clicked)
        self._update_info_label()
        self._update_row_count_label()
        self._update_column_count_label()

    def _setup_layout(self):
        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)
        top_row.addWidget(self.ui.btnLoadAll)
        top_row.addWidget(self.ui.btnLoadSelected)
        top_row.addWidget(self.ui.btnRefresh)
        top_row.addSpacing(12)

        self.lblSearch = QLabel("Search:", self)
        self.lblSearch.setObjectName("lblSearch")
        top_row.addWidget(self.lblSearch)
        self.ui.lineSearch.setClearButtonEnabled(True)
        top_row.addWidget(self.ui.lineSearch, 1)

        self.lblColumnPreset = QLabel("Preset:", self)
        self.lblColumnPreset.setObjectName("lblColumnPreset")
        top_row.addWidget(self.lblColumnPreset)
        self.comboColumnPreset = QComboBox(self)
        self.comboColumnPreset.setObjectName("comboColumnPreset")
        self.comboColumnPreset.addItems(list(self.COLUMN_PRESETS.keys()))
        top_row.addWidget(self.comboColumnPreset)

        self.lblColumnSearch = QLabel("Columns:", self)
        self.lblColumnSearch.setObjectName("lblColumnSearch")
        top_row.addWidget(self.lblColumnSearch)
        self.lineColumnSearch = QLineEdit(self)
        self.lineColumnSearch.setObjectName("lineColumnSearch")
        self.lineColumnSearch.setPlaceholderText("Search columns...")
        self.lineColumnSearch.setClearButtonEnabled(True)
        top_row.addWidget(self.lineColumnSearch, 1)

        self.btnResetLayout = QPushButton("Reset layout", self)
        self.btnResetLayout.setObjectName("btnResetLayout")
        top_row.addWidget(self.btnResetLayout)

        self.lblColumnCount = QLabel("Columns: 0 / 0", self)
        self.lblColumnCount.setObjectName("lblColumnCount")
        self.lblColumnCount.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Preferred)
        top_row.addWidget(self.lblColumnCount)

        self.lblRowCount = QLabel("Rows: 0 / 0", self)
        self.lblRowCount.setObjectName("lblRowCount")
        self.lblRowCount.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Preferred)
        top_row.addWidget(self.lblRowCount)

        top_row.addStretch(1)
        top_row.addWidget(self.ui.btnExport)

        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        root.addLayout(top_row)
        root.addWidget(self.ui.tablePreview, 1)

    def _configure_table(self):
        self.ui.tablePreview.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.tablePreview.customContextMenuRequested.connect(self._show_cell_context_menu)
        header = self.ui.tablePreview.horizontalHeader()
        header.setContextMenuPolicy(Qt.CustomContextMenu)
        header.customContextMenuRequested.connect(self._show_header_context_menu)
        header.setSectionsMovable(True)
        self.ui.tablePreview.verticalHeader().setVisible(False)
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(56)

    # ---- публичный API ----
    def set_records(self, records: list[dict]):
        self._records = deepcopy(records or [])
        self._snapshot = deepcopy(self._records)
        self._rebuild_table(self._snapshot)

    # ---- внутренняя логика ----
    def _all_keys(self) -> list[str]:
        keys = set()
        for r in self._records:
            keys.update(r.keys())
        return xb.preview_column_order([{k: "" for k in keys}])

    def _rebuild_table(self, records: list[dict] | None = None, preserve_layout: bool = True):
        """Перерисовать tablePreview по снапшоту/records (стабильно, без "плывущих" колонок)."""
        records = records or getattr(self, "_snapshot", []) or []
        t = self.ui.tablePreview
        records = xb.normalize_preview_rows(records)
        self._preview_records = deepcopy(records)
        if preserve_layout:
            self._capture_column_order()
            self._capture_column_widths()

        # 2) Reset таблицы (жёстко)
        t.setSortingEnabled(False)
        t.setUpdatesEnabled(False)
        t.clear()
        t.setRowCount(0)
        t.setColumnCount(0)

        if not records:
            t.setUpdatesEnabled(True)
            t.setSortingEnabled(True)
            self._update_info_label()
            self._update_row_count_label()
            self._update_column_count_label()
            return

        # 3) Стабильный порядок колонок: preferred -> остальные
        keys = set()
        for r in records:
            keys.update(r.keys())

        keys_order = xb.preview_column_order(records)

        t.setColumnCount(len(keys_order))
        t.setHorizontalHeaderLabels(keys_order)

        # 4) Заполнение
        t.setRowCount(len(records))
        for row, rec in enumerate(records):
            for col, key in enumerate(keys_order):
                raw_val = rec.get(key, "")
                val = raw_val

                # вложенные структуры -> компактный текст + красивый tooltip
                text, pretty = self._to_cell(val)
                item = QTableWidgetItem(text)
                if pretty:
                    item.setToolTip(pretty)
                elif len(text) > 80:
                    item.setToolTip(text)

                if isinstance(val, (int, float)):
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

                item.setData(Qt.UserRole, row)
                t.setItem(row, col, item)

        self._apply_column_resize_policy(keys_order)
        self._restore_column_widths()
        if preserve_layout:
            self._restore_column_order()
        else:
            self._restore_default_column_order()
        self._apply_column_visibility_filters()
        t.setUpdatesEnabled(True)
        t.setSortingEnabled(True)
        self._columns = keys_order
        self._update_info_label()
        self._update_row_count_label()

    @Slot()
    def _reset_column_layout(self):
        self._column_widths_by_name.clear()
        self._column_order_by_name.clear()
        self._rebuild_table(getattr(self, "_snapshot", []), preserve_layout=False)
        self.on_filter_changed(self.ui.lineSearch.text())

    def _capture_column_order(self):
        t = self.ui.tablePreview
        header = t.horizontalHeader()
        order: list[str] = []
        seen: set[str] = set()
        for visual_idx in range(header.count()):
            logical_idx = header.logicalIndex(visual_idx)
            if logical_idx < 0 or logical_idx >= t.columnCount():
                continue
            item = t.horizontalHeaderItem(logical_idx)
            header_text = item.text().strip() if item and item.text() else ""
            if not header_text or header_text in seen:
                continue
            order.append(header_text)
            seen.add(header_text)
        if order:
            self._column_order_by_name = order

    def _restore_column_order(self):
        if not self._column_order_by_name:
            return

        t = self.ui.tablePreview
        header = t.horizontalHeader()
        logical_by_name: dict[str, int] = {}
        for col in range(t.columnCount()):
            item = t.horizontalHeaderItem(col)
            header_text = item.text().strip() if item and item.text() else ""
            if header_text and header_text not in logical_by_name:
                logical_by_name[header_text] = col

        target_visual_idx = 0
        for header_text in self._column_order_by_name:
            logical_idx = logical_by_name.get(header_text)
            if logical_idx is None:
                continue
            current_visual_idx = header.visualIndex(logical_idx)
            if current_visual_idx < 0:
                continue
            if current_visual_idx != target_visual_idx:
                header.moveSection(current_visual_idx, target_visual_idx)
            target_visual_idx += 1

    def _restore_default_column_order(self):
        t = self.ui.tablePreview
        header = t.horizontalHeader()
        for logical_idx in range(t.columnCount()):
            current_visual_idx = header.visualIndex(logical_idx)
            if current_visual_idx >= 0 and current_visual_idx != logical_idx:
                header.moveSection(current_visual_idx, logical_idx)

    def _capture_column_widths(self):
        t = self.ui.tablePreview
        widths: dict[str, int] = {}
        for col in range(t.columnCount()):
            item = t.horizontalHeaderItem(col)
            header_text = item.text().strip() if item and item.text() else ""
            if not header_text:
                continue
            width = t.columnWidth(col)
            if width > 0:
                widths[header_text] = width
        if widths:
            self._column_widths_by_name.update(widths)

    def _restore_column_widths(self):
        if not self._column_widths_by_name:
            return

        t = self.ui.tablePreview
        for col in range(t.columnCount()):
            item = t.horizontalHeaderItem(col)
            header_text = item.text().strip() if item and item.text() else ""
            width = self._column_widths_by_name.get(header_text)
            if width:
                t.setColumnWidth(col, width)

    def _apply_column_resize_policy(self, columns: list[str]):
        t = self.ui.tablePreview
        header = t.horizontalHeader()
        header.setStretchLastSection(False)

        readable_widths = {"url": 420, "final_url": 420, "title": 260}
        tight_cols = {"status_code", "redirects", "request_ms", "content_len"}
        fixed_width = {"task_id": 170}

        for idx, col in enumerate(columns):
            header.setSectionResizeMode(idx, QHeaderView.ResizeMode.Interactive)

            if col in readable_widths:
                t.setColumnWidth(idx, readable_widths[col])
            elif col in tight_cols:
                t.resizeColumnToContents(idx)
                t.setColumnWidth(idx, max(76, min(t.columnWidth(idx), 140)))
            elif col in fixed_width:
                t.setColumnWidth(idx, fixed_width[col])
            else:
                t.resizeColumnToContents(idx)

    def _update_info_label(self):
        table = self.ui.tablePreview
        total = table.rowCount()
        visible = 0
        for row in range(total):
            if not table.isRowHidden(row):
                visible += 1
        if hasattr(self, "lblInfo"):
            self.lblInfo.setText(f"Rows: {total} | Visible: {visible}")

    def _update_column_count_label(self):
        table = self.ui.tablePreview
        total = table.columnCount()
        visible = 0
        for col in range(total):
            if not table.isColumnHidden(col):
                visible += 1
        if hasattr(self, "lblColumnCount"):
            self.lblColumnCount.setText(f"Columns: {visible} / {total}")

    def _update_row_count_label(self):
        table = self.ui.tablePreview
        total = table.rowCount()
        visible = 0
        for row in range(total):
            if not table.isRowHidden(row):
                visible += 1
        if hasattr(self, "lblRowCount"):
            self.lblRowCount.setText(f"Rows: {visible} / {total}")

    def _to_cell(self, val):
        if isinstance(val, (dict, list)):
            compact = json.dumps(val, ensure_ascii=False, separators=(",", ":"))
            pretty = json.dumps(val, ensure_ascii=False, indent=2)
            text = compact if len(compact) < 120 else compact[:117] + "…"
            return text, pretty
        if val is None:
            return "", ""
        s = str(val)
        return (s[:200] + "…", s) if len(s) > 200 else (s, "")

    # ---- cell context menu ----
    def _show_cell_context_menu(self, pos):
        table = self.ui.tablePreview
        item = table.itemAt(pos)
        if item is None:
            return

        row = item.row()
        col = item.column()
        if row < 0 or col < 0:
            return

        menu = QMenu(table)
        menu.addAction("Copy cell", lambda: self._copy_cell_value(row, col))
        menu.addAction("Open cell in Viewer", lambda: self._open_cell_in_viewer(row, col))
        menu.addSeparator()
        menu.addAction("Copy row as JSON", lambda: self._copy_row_as_json(row))
        menu.addAction("Open row in Viewer", lambda: self._open_row_in_viewer(row))
        menu.exec(table.viewport().mapToGlobal(pos))

    def _record_index_for_table_row(self, row: int) -> int | None:
        table = self.ui.tablePreview
        if not (0 <= row < table.rowCount()):
            return None

        for col in range(table.columnCount()):
            item = table.item(row, col)
            if item is None:
                continue
            record_index = item.data(Qt.UserRole)
            if isinstance(record_index, int):
                return record_index

        return row if 0 <= row < len(getattr(self, "_snapshot", [])) else None

    def _header_key_for_column(self, col: int) -> str:
        table = self.ui.tablePreview
        if not (0 <= col < table.columnCount()):
            return ""
        header = table.horizontalHeaderItem(col)
        return header.text().strip() if header and header.text() else ""

    def _source_record_for_table_row(self, row: int) -> dict:
        record_index = self._record_index_for_table_row(row)
        records = getattr(self, "_snapshot", None) or self._records
        if record_index is None or not (0 <= record_index < len(records)):
            return {}
        rec = records[record_index]
        return rec if isinstance(rec, dict) else {"value": rec}

    def _preview_record_for_table_row(self, row: int) -> dict:
        record_index = self._record_index_for_table_row(row)
        records = getattr(self, "_preview_records", [])
        if record_index is None or not (0 <= record_index < len(records)):
            return {}
        rec = records[record_index]
        return rec if isinstance(rec, dict) else {"value": rec}

    def _cell_value_for_table_position(self, row: int, col: int):
        key = self._header_key_for_column(col)
        if not key:
            return None

        source_record = self._source_record_for_table_row(row)
        if key in source_record:
            return source_record.get(key)

        preview_record = self._preview_record_for_table_row(row)
        return preview_record.get(key)

    def _value_to_clipboard_text(self, value) -> str:
        if isinstance(value, (dict, list)):
            return json.dumps(value, indent=2, ensure_ascii=False, default=str)
        if value is None:
            return ""
        return str(value)

    def _value_to_column_clipboard_text(self, value) -> str:
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
        if value is None:
            return ""
        return str(value)

    # ---- header context menu ----
    def _show_header_context_menu(self, pos):
        table = self.ui.tablePreview
        header = table.horizontalHeader()
        col = header.logicalIndexAt(pos)
        if col < 0 or col >= table.columnCount() or table.isColumnHidden(col):
            return

        key = self._header_key_for_column(col)
        if not key:
            return

        menu = QMenu(header)
        menu.addAction("Copy column name", lambda: self._copy_column_name(col))
        menu.addAction("Copy visible column values", lambda: self._copy_visible_column_values(col))
        menu.addAction("Open column in Viewer", lambda: self._open_column_in_viewer(col))
        menu.addSeparator()
        menu.addAction("Resize column to contents", lambda: self._resize_column_to_contents(col))
        menu.exec(header.viewport().mapToGlobal(pos))

    def _copy_column_name(self, col: int):
        key = self._header_key_for_column(col)
        if key:
            QApplication.clipboard().setText(key)

    def _visible_column_values(self, col: int) -> list:
        key = self._header_key_for_column(col)
        if not key:
            return []

        table = self.ui.tablePreview
        values = []
        for row in range(table.rowCount()):
            if table.isRowHidden(row):
                continue
            values.append(self._cell_value_for_table_position(row, col))
        return values

    def _copy_visible_column_values(self, col: int):
        values = self._visible_column_values(col)
        text = "\n".join(self._value_to_column_clipboard_text(value) for value in values)
        QApplication.clipboard().setText(text)

    def _open_column_in_viewer(self, col: int):
        key = self._header_key_for_column(col)
        if not key:
            return

        values = self._visible_column_values(col)
        UniversalViewerDialog(
            title=f"Data Preview - Column: {key}",
            payload={
                "column": key,
                "visible_row_count": len(values),
                "visible_values": values,
            },
            parent=self,
            save_dialog_title="Save Data Preview Column",
            default_save_stem=f"data_preview_column_{key or 'column'}",
        ).exec()

    def _resize_column_to_contents(self, col: int):
        table = self.ui.tablePreview
        if not (0 <= col < table.columnCount()) or table.isColumnHidden(col):
            return

        table.resizeColumnToContents(col)
        key = self._header_key_for_column(col)
        if key:
            self._column_widths_by_name[key] = table.columnWidth(col)

    def _copy_cell_value(self, row: int, col: int):
        value = self._cell_value_for_table_position(row, col)
        QApplication.clipboard().setText(self._value_to_clipboard_text(value))

    def _open_cell_in_viewer(self, row: int, col: int):
        key = self._header_key_for_column(col)
        if not key:
            return

        value = self._cell_value_for_table_position(row, col)
        title = f"Data Preview - {key}"
        if isinstance(value, (dict, list)):
            UniversalViewerDialog(
                title=title,
                payload=value,
                parent=self,
                save_dialog_title="Save Data Preview Cell",
                default_save_stem=f"data_preview_{key or 'cell'}",
            ).exec()
            return

        UniversalViewerDialog(
            title=title,
            content=self._value_to_clipboard_text(value),
            parent=self,
            save_dialog_title="Save Data Preview Cell",
            default_save_stem=f"data_preview_{key or 'cell'}",
        ).exec()

    def _copy_row_as_json(self, row: int):
        record = self._source_record_for_table_row(row)
        if not record:
            return
        text = json.dumps(record, indent=2, ensure_ascii=False, default=str)
        QApplication.clipboard().setText(text)

    # ---- действия тулбара ----
    def _open_row_in_viewer(self, row: int):
        record = self._source_record_for_table_row(row)
        if not record:
            return

        title = "Row details"
        row_label = record.get("url") or record.get("final_url") or record.get("task_id")
        if row_label:
            title = f"{title}: {row_label}"

        UniversalViewerDialog(
            title=title,
            payload=record,
            parent=self,
            save_dialog_title="Save Data Preview Row",
            default_save_stem="data_preview_row",
        ).exec()

    @Slot()
    def on_load_all(self):
        if callable(self.fetch_all):
            self.set_records(self.fetch_all())

    @Slot()
    def on_load_selected(self):
        if callable(self.fetch_selected):
            self.set_records(self.fetch_selected())

    @Slot()
    def on_refresh(self):
        if self._records:
            self._rebuild_table()
        else:
            self.on_load_all()

    @Slot()
    def on_export_clicked(self):
        # 1) Берём текущий снимок (только то, что сейчас в предпросмотре)
        records = getattr(self, "_snapshot", None) or []
        if not records:
            QMessageBox.information(self, "Export", "Nothing to export (snapshot is empty).")
            return

        # 2) Диалог сохранения: CSV/JSON/XLSX
        path, fmt = self._ask_export_path()
        if not path:
            return

        # 3) Экспорт через единый мост
        try:
            xb.export(records, path, fmt=fmt)
        except Exception as e:
            QMessageBox.critical(self, "Export failed", f"{e}")
            # если хочешь прокинуть в логи вкладки:
            if hasattr(self, "export_failed"):
                try: self.export_failed.emit(str(e))
                except Exception: pass
            return

        QMessageBox.information(self, "Export", f"Saved {len(records)} rows →\n{path}")
        # опционально: открыть папку
        try:
            folder = os.path.dirname(os.path.abspath(path))
            QFileDialog.getOpenFileName(self, "Open folder", folder)  # дешёвый трюк, можно убрать
        except Exception:
            pass

        # если хочешь отдать в лог ScraperTab:
        if hasattr(self, "export_done"):
            try: self.export_done.emit(path, len(records))
            except Exception: pass
            
    def _ask_export_path(self) -> tuple[str, str]:
        """
        Возвращает (path, fmt) где fmt in {'csv','json','xlsx'}.
        """
        # дефолтная папка
        base_dir = os.path.join("data", "exports")
        os.makedirs(base_dir, exist_ok=True)

        ts = QDateTime.currentDateTime().toString("yyyyMMdd_HHmmss")
        base_name = f"data_preview_{ts}"
        filters = "CSV (*.csv);;JSON (*.json);;Excel (*.xlsx)"

        path, selected = QFileDialog.getSaveFileName(
            self,
            "Export snapshot…",
            os.path.join(base_dir, base_name + ".csv"),
            filters
        )
        if not path:
            return "", ""

        # Определим fmt по выбранному фильтру/расширению
        selected = (selected or "").lower()
        if "json" in selected or path.lower().endswith(".json"):
            fmt = "json"
            if not path.lower().endswith(".json"):
                path += ".json"
        elif "xlsx" in selected or path.lower().endswith(".xlsx"):
            fmt = "xlsx"
            if not path.lower().endswith(".xlsx"):
                path += ".xlsx"
        else:
            fmt = "csv"
            if not path.lower().endswith(".csv"):
                path += ".csv"

        return path, fmt



    def _export_records(self, records: list[dict], path: str):
        import os, csv
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # JSON
        if path.lower().endswith(".json"):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(records, f, ensure_ascii=False, indent=2)
            return
        # XLSX
        if path.lower().endswith(".xlsx"):
            try:
                from openpyxl import Workbook
                wb = Workbook(); ws = wb.active
                cols = self._columns or sorted({k for r in records for k in r.keys()})
                ws.append(cols)
                for r in records:
                    row = [json.dumps(r.get(c), ensure_ascii=False) if isinstance(r.get(c), (dict, list))
                           else r.get(c) for c in cols]
                    ws.append(row)
                wb.save(path)
                return
            except Exception:
                # fallback → JSON рядом
                p = os.path.splitext(path)[0] + ".json"
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(records, f, ensure_ascii=False, indent=2)
                return
        # CSV
        cols = self._columns or sorted({k for r in records for k in r.keys()})
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            for r in records:
                row = {}
                for c in cols:
                    v = r.get(c)
                    row[c] = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v
                w.writerow(row)

    # ---- поиск / фильтр ----
    @Slot(str)
    def on_filter_changed(self, text: str):
        needle = (text or "").strip().lower()
        tbl = self.ui.tablePreview
        tbl.setUpdatesEnabled(False)
        for row in range(tbl.rowCount()):
            visible = False if needle else True
            if needle:
                for col in range(tbl.columnCount()):
                    it = tbl.item(row, col)
                    if it and needle in it.text().lower():
                        visible = True; break
            tbl.setRowHidden(row, not visible)
        tbl.setUpdatesEnabled(True)
        self._update_info_label()
        self._update_row_count_label()

    @Slot(str)
    def _apply_column_filter(self, text: str | None = None):
        self._apply_column_visibility_filters(text)

    def _current_preset_name(self) -> str:
        if not hasattr(self, "comboColumnPreset"):
            return self.PRESET_ALL_COLUMNS
        preset_name = (self.comboColumnPreset.currentText() or "").strip()
        return preset_name if preset_name in self.COLUMN_PRESETS else self.PRESET_ALL_COLUMNS

    def _column_matches_preset(self, header_text: str) -> bool:
        preset_name = self._current_preset_name()
        if preset_name == self.PRESET_ALL_COLUMNS:
            return True

        header = (header_text or "").strip().lower()
        if not header:
            return False

        core_columns = {name.lower() for name in self.CORE_IDENTITY_COLUMNS}
        if header in core_columns:
            return True

        patterns = self.COLUMN_PRESETS.get(preset_name, ())
        return any(pattern.lower() in header for pattern in patterns)

    @Slot(str)
    def _apply_column_visibility_filters(self, text: str | None = None):
        if text is None:
            text = self.lineColumnSearch.text() if hasattr(self, "lineColumnSearch") else ""
        needle = (text or "").strip().lower()
        tbl = self.ui.tablePreview
        tbl.setUpdatesEnabled(False)
        for col in range(tbl.columnCount()):
            item = tbl.horizontalHeaderItem(col)
            header_text = item.text().strip() if item and item.text() else ""
            header_lower = header_text.lower()
            matches_preset = self._column_matches_preset(header_text)
            matches_search = not needle or needle in header_lower
            tbl.setColumnHidden(col, not (matches_preset and matches_search))
        tbl.setUpdatesEnabled(True)
        self._update_column_count_label()

    # ---- dbl-click ----
    @Slot(int, int)
    def on_cell_dbl_clicked(self, row: int, col: int):
        key = self._header_key_for_column(col)
        if not key:
            return

        val = self._cell_value_for_table_position(row, col)
        if isinstance(val, (dict, list)):
            UniversalViewerDialog(
                title=key or "Data Preview",
                payload=val,
                parent=self,
                save_dialog_title="Save Data Preview Cell",
                default_save_stem=f"data_preview_{key or 'cell'}",
            ).exec()
        elif key in ("final_url", "url"):
            from PySide6.QtGui import QDesktopServices
            from PySide6.QtCore import QUrl
            if val:
                QDesktopServices.openUrl(QUrl(str(val)))
