# dialogs/data_preview_dialog.py
from __future__ import annotations
import json, os
from ui import export_bridge as xb
from typing import Callable, Iterable
from PySide6.QtWidgets import QDialog, QTableWidgetItem, QFileDialog, QMessageBox
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
        
          

        self.fetch_all = fetch_all
        self.fetch_selected = fetch_selected
        self._records: list[dict] = []
        self._columns: list[str] = []

        # signals
        self.ui.btnLoadAll.clicked.connect(self.on_load_all)
        self.ui.btnLoadSelected.clicked.connect(self.on_load_selected)
        self.ui.btnRefresh.clicked.connect(self.on_refresh)
        self.ui.btnExport.clicked.connect(self.on_export_clicked)
        self.ui.lineSearch.textChanged.connect(self.on_filter_changed)
        self.ui.tablePreview.cellDoubleClicked.connect(self.on_cell_dbl_clicked)

    # ---- публичный API ----
    def set_records(self, records: list[dict]):
        self._snapshot = list(records or [])
        try:
            self._rebuild_table(self._snapshot)
        except TypeError:
            self._rebuild_table()




    # ---- внутренняя логика ----
    def _all_keys(self) -> list[str]:
        keys = set()
        for r in self._records:
            keys.update(r.keys())
        preferred = ["final_url", "status_code", "title", "content_len", "request_ms", "redirects"]
        rest = sorted(k for k in keys if k not in preferred)
        return [c for c in preferred if c in keys] + rest

    def _rebuild_table(self, records: list[dict] | None = None):
        """Перерисовать tablePreview по снапшоту/records."""
        records = records or getattr(self, "_snapshot", []) or []
        t = self.ui.tablePreview

        # чистим
        t.setSortingEnabled(False)
        t.clear()
        t.setRowCount(0)
        t.setColumnCount(0)

        if not records:
            return

        # объединяем ключи по всем записям (стабильный порядок)
        keys_order = []
        seen = set()
        # сначала возьмём порядок по первой записи
        for k in records[0].keys():
            keys_order.append(k); seen.add(k)
        # затем добавим недостающие из остальных
        for rec in records[1:]:
            for k in rec.keys():
                if k not in seen:
                    keys_order.append(k); seen.add(k)

        t.setColumnCount(len(keys_order))
        t.setHorizontalHeaderLabels(keys_order)

        # заполняем
        for r, rec in enumerate(records):
            t.insertRow(r)
            for c, k in enumerate(keys_order):
                val = rec.get(k, "")
                if isinstance(val, (dict, list, tuple)):
                    val = str(val)
                elif val is None:
                    val = ""
                item = QTableWidgetItem(str(val))
                # удобные тултипы для длинных значений
                if len(str(val)) > 80:
                    item.setToolTip(str(val))
                t.setItem(r, c, item)

        t.resizeColumnsToContents()
        t.setSortingEnabled(True)

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
