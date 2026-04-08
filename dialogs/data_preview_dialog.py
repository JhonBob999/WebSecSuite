# dialogs/data_preview_dialog.py
from __future__ import annotations
import json, os
from copy import deepcopy
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
        self._records = deepcopy(records or [])
        self._snapshot = deepcopy(self._records)
        self._rebuild_table(self._snapshot)

    # ---- внутренняя логика ----
    def _all_keys(self) -> list[str]:
        keys = set()
        for r in self._records:
            keys.update(r.keys())
        preferred = ["final_url", "status_code", "title", "content_len", "request_ms", "redirects"]
        rest = sorted(k for k in keys if k not in preferred)
        return [c for c in preferred if c in keys] + rest

    def _rebuild_table(self, records: list[dict] | None = None):
        """Перерисовать tablePreview по снапшоту/records (стабильно, без "плывущих" колонок)."""
        records = records or getattr(self, "_snapshot", []) or []
        t = self.ui.tablePreview

        def _norm_key(k) -> str:
            if k is None:
                return "__none__"
            s = str(k).replace("\ufeff", "").strip()  # убираем BOM/пробелы
            return s if s else "__empty__"

        # 1) Нормализуем записи: ключи -> нормальные строки, убираем пустые/кривые
        norm_records: list[dict] = []
        for rec in records:
            if not isinstance(rec, dict):
                rec = {"value": rec}
            nr = {}
            for k, v in rec.items():
                nk = _norm_key(k)
                if nk in nr:
                    i = 2
                    while f"{nk}#{i}" in nr:
                        i += 1
                    nk = f"{nk}#{i}"
                nr[nk] = v
            norm_records.append(nr)

        records = norm_records

        # 2) Reset таблицы (жёстко)
        t.setSortingEnabled(False)
        t.setUpdatesEnabled(False)
        t.clear()
        t.setRowCount(0)
        t.setColumnCount(0)

        if not records:
            t.setUpdatesEnabled(True)
            t.setSortingEnabled(True)
            return

        # 3) Стабильный порядок колонок: preferred -> остальные
        keys = set()
        for r in records:
            keys.update(r.keys())

        preferred = ["final_url", "status_code", "title", "content_len", "request_ms", "redirects"]
        rest = sorted(k for k in keys if k not in preferred)
        keys_order = [k for k in preferred if k in keys] + rest

        t.setColumnCount(len(keys_order))
        t.setHorizontalHeaderLabels(keys_order)

        # 4) Заполнение
        t.setRowCount(len(records))
        for row, rec in enumerate(records):
            for col, key in enumerate(keys_order):
                raw_val = rec.get(key, "")
                val = self._compact_preview_value(key, raw_val)

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

        t.resizeColumnsToContents()
        t.setUpdatesEnabled(True)
        t.setSortingEnabled(True)
        self._columns = keys_order



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

    def _compact_preview_value(self, key: str, val):
        if key == "forms_summary" and isinstance(val, dict):
            fs = val
            return (
                f"total={fs.get('forms_total', 0)}, "
                f"unique={fs.get('forms_unique', fs.get('forms_total', 0))}, "
                f"inputs={fs.get('inputs_total', 0)}, "
                f"unique_inputs={fs.get('inputs_unique_total', fs.get('inputs_total', 0))}, "
                f"names={fs.get('unique_input_names', 0)}"
            )
        if key == "forms" and isinstance(val, list):
            return self._compact_forms(val)
        return val

    def _compact_forms(self, forms: list) -> str:
        if not forms:
            return "[]"
        parts = []
        max_forms = 2
        for idx, form in enumerate(forms[:max_forms], 1):
            method = (form.get("method") or "").upper()
            action = str(form.get("action") or "")
            action_short = action if len(action) <= 120 else action[:119] + "…"
            enctype = form.get("enctype") or ""
            inputs_count = form.get("inputs_count") or len(form.get("inputs", []) or [])
            has_file = 1 if form.get("has_file") else 0
            names = form.get("input_names") or []
            names_short = ", ".join((n or "") for n in names[:10])
            if len(names) > 10:
                names_short += ", …"
            parts.append(
                f"[{idx}] {method} {action_short} enctype={enctype} inputs={inputs_count} file={has_file} names={names_short}"
            )
        if len(forms) > max_forms:
            parts.append(f"... +{len(forms) - max_forms} more")
        out = " | ".join(parts)
        return out if len(out) <= 2000 else out[:1999] + "…"

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
