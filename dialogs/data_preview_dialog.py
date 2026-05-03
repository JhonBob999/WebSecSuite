# dialogs/data_preview_dialog.py
from __future__ import annotations
import json, os
from copy import deepcopy
from ui import export_bridge as xb
from typing import Callable
from PySide6.QtWidgets import (
    QDialog,
    QTableWidgetItem,
    QFileDialog,
    QMessageBox,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QSizePolicy,
    QHeaderView,
)
from PySide6.QtCore import Qt, Slot, QDateTime, Signal

from dialogs.ui.data_preview_dialog_ui import Ui_DataPreviewDialog  # сгенерённый класс


class DataPreviewDialog(QDialog):
    export_done = Signal(str, int)
    export_failed = Signal(str)
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
        self._column_widths: dict[str, int] = {}

        # signals
        self.ui.btnLoadAll.clicked.connect(self.on_load_all)
        self.ui.btnLoadSelected.clicked.connect(self.on_load_selected)
        self.ui.btnRefresh.clicked.connect(self.on_refresh)
        self.ui.btnExport.clicked.connect(self.on_export_clicked)
        self.ui.lineSearch.textChanged.connect(self.on_filter_changed)
        self.ui.tablePreview.cellDoubleClicked.connect(self.on_cell_dbl_clicked)
        self._update_info_label()

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
        top_row.addWidget(self.ui.lineSearch, 1)

        self.lblInfo = QLabel("Rows: 0 | Visible: 0", self)
        self.lblInfo.setObjectName("lblInfo")
        self.lblInfo.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Preferred)
        top_row.addWidget(self.lblInfo)
        top_row.addStretch(1)
        top_row.addWidget(self.ui.btnExport)

        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        root.addLayout(top_row)
        root.addWidget(self.ui.tablePreview, 1)

    def _configure_table(self):
        header = self.ui.tablePreview.horizontalHeader()
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

    def _rebuild_table(self, records: list[dict] | None = None):
        """Перерисовать tablePreview по снапшоту/records (стабильно, без "плывущих" колонок)."""
        records = records or getattr(self, "_snapshot", []) or []
        t = self.ui.tablePreview
        records = xb.normalize_preview_rows(records)
        self._column_widths.update(self._capture_column_widths())

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

                t.setItem(row, col, item)

        self._apply_column_resize_policy(keys_order)
        self._restore_column_widths(keys_order)
        t.setUpdatesEnabled(True)
        t.setSortingEnabled(True)
        self._columns = keys_order
        self._update_info_label()

    def _capture_column_widths(self) -> dict[str, int]:
        t = self.ui.tablePreview
        widths: dict[str, int] = {}
        for idx in range(t.columnCount()):
            item = t.horizontalHeaderItem(idx)
            column = item.text() if item else ""
            width = t.columnWidth(idx)
            if column and width > 0:
                widths[column] = width
        return widths

    def _restore_column_widths(self, columns: list[str]):
        t = self.ui.tablePreview
        header = t.horizontalHeader()
        for idx, column in enumerate(columns):
            width = self._column_widths.get(column)
            if width:
                header.setSectionResizeMode(idx, QHeaderView.ResizeMode.Interactive)
                t.setColumnWidth(idx, width)

    def _apply_column_resize_policy(self, columns: list[str]):
        t = self.ui.tablePreview
        header = t.horizontalHeader()

        preferred_width = {
            "url": 360,
            "final_url": 420,
            "title": 280,
        }
        tight_cols = {"status_code", "redirects", "request_ms", "content_len"}
        fixed_width = {"task_id": 170}

        for idx, col in enumerate(columns):
            if col in preferred_width:
                header.setSectionResizeMode(idx, QHeaderView.ResizeMode.Interactive)
                t.setColumnWidth(idx, preferred_width[col])
            elif col in tight_cols:
                header.setSectionResizeMode(idx, QHeaderView.ResizeMode.ResizeToContents)
            elif col in fixed_width:
                header.setSectionResizeMode(idx, QHeaderView.ResizeMode.Interactive)
                t.setColumnWidth(idx, fixed_width[col])
            else:
                header.setSectionResizeMode(idx, QHeaderView.ResizeMode.Interactive)
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

    # ---- действия тулбара ----
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

    # ---- dbl-click ----
    @Slot(int, int)
    def on_cell_dbl_clicked(self, row: int, col: int):
        key = self._columns[col]
        rec = self._records[row] if 0 <= row < len(self._records) else {}
        val = rec.get(key)
        if isinstance(val, (dict, list)):
            pretty = json.dumps(val, ensure_ascii=False, indent=2)
            QMessageBox.information(self, key, pretty)
        elif key in ("final_url", "url"):
            from PySide6.QtGui import QDesktopServices
            from PySide6.QtCore import QUrl
            if val:
                QDesktopServices.openUrl(QUrl(str(val)))
