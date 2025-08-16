# dialogs/data_preview_dialog.py
from __future__ import annotations
import json
from typing import Callable, Iterable
from PySide6.QtWidgets import QDialog, QTableWidgetItem, QFileDialog, QMessageBox
from PySide6.QtCore import Qt, Slot

from dialogs.ui.data_preview_dialog_ui import Ui_DataPreviewDialog  # сгенерённый класс

class DataPreviewDialog(QDialog):
    def __init__(self, parent=None,
                 fetch_all: Callable[[], list[dict]] | None = None,
                 fetch_selected: Callable[[], list[dict]] | None = None):
        super().__init__(parent)
        self.ui = Ui_DataPreviewDialog()
        self.ui.setupUi(self)

        self.fetch_all = fetch_all
        self.fetch_selected = fetch_selected
        self._records: list[dict] = []
        self._columns: list[str] = []

        # signals
        self.ui.btnLoadAll.clicked.connect(self.on_load_all)
        self.ui.btnLoadSelected.clicked.connect(self.on_load_selected)
        self.ui.btnRefresh.clicked.connect(self.on_refresh)
        self.ui.btnExport.clicked.connect(self.on_export)
        self.ui.lineSearch.textChanged.connect(self.on_filter_changed)
        self.ui.tablePreview.cellDoubleClicked.connect(self.on_cell_dbl_clicked)

    # ---- публичный API ----
    def set_records(self, records: list[dict]):
        self._records = records or []
        self._rebuild_table()

    # ---- внутренняя логика ----
    def _all_keys(self) -> list[str]:
        keys = set()
        for r in self._records:
            keys.update(r.keys())
        preferred = ["final_url", "status_code", "title", "content_len", "request_ms", "redirects"]
        rest = sorted(k for k in keys if k not in preferred)
        return [c for c in preferred if c in keys] + rest

    def _rebuild_table(self):
        self._columns = self._all_keys()
        tbl = self.ui.tablePreview
        tbl.clear()
        tbl.setColumnCount(len(self._columns))
        tbl.setHorizontalHeaderLabels(self._columns)
        tbl.setRowCount(len(self._records))

        for row, rec in enumerate(self._records):
            for col, key in enumerate(self._columns):
                val = rec.get(key, "")
                text, tooltip = self._to_cell(val)
                item = QTableWidgetItem(text)
                if tooltip and tooltip != text:
                    item.setToolTip(tooltip)
                # числа вправо
                if isinstance(val, (int, float)) or (isinstance(val, str) and val.isdigit()):
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                tbl.setItem(row, col, item)

        tbl.resizeColumnsToContents()
        tbl.resizeRowsToContents()

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
    def on_export(self):
        if not self._records:
            QMessageBox.information(self, "Export", "Nothing to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Preview", "data/exports/preview_export",
            "CSV (*.csv);;JSON (*.json);;Excel (*.xlsx)"
        )
        if not path:
            return
        try:
            self._export_records(self._records, path)
            QMessageBox.information(self, "Export", f"Saved → {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export error", str(e))

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
