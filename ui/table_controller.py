# ui/table_controller.py
from __future__ import annotations
from ui.constants import Col
from typing import Optional, Iterable, Dict, List, Tuple
from PySide6.QtCore import Qt, QSettings
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView

# Роль, в которой храним task_id внутри ячейки (URL-колонки достаточно)
ROLE_TASK_ID = Qt.UserRole + 1

class TaskTableController:
    def __init__(self, table: QTableWidget):
        self.table = table
        self._col_index_cache: Dict[str, int] = {}
        self._setup_table_base()
        
        
    def apply_common_view_settings(self):
        t = self.table
        t.verticalHeader().setVisible(False)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.setSelectionMode(QAbstractItemView.ExtendedSelection)
        t.setAlternatingRowColors(True)
        
        # ---------- Политики размеров ----------
    def setup_resize_policies(self):
        header = self.table.horizontalHeader()
        vheader = self.table.verticalHeader()
        if header:
            header.setSectionResizeMode(Col.URL,     QHeaderView.ResizeToContents)
            header.setSectionResizeMode(Col.Status,  QHeaderView.ResizeToContents)
            header.setSectionResizeMode(Col.Code,    QHeaderView.ResizeToContents)
            header.setSectionResizeMode(Col.Time,    QHeaderView.ResizeToContents)
            header.setSectionResizeMode(Col.Results, QHeaderView.Stretch)
            header.setSectionResizeMode(Col.Cookies, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(Col.Params,  QHeaderView.ResizeToContents)
            header.setStretchLastSection(True)
        if vheader:
            vheader.setSectionResizeMode(QHeaderView.ResizeToContents)

    # ---------- Сохранение/восстановление ширин ----------
    def save_column_widths(self, settings: QSettings, group: str = "taskTable"):
        header = self.table.horizontalHeader()
        if not header:
            return
        cols = self.table.columnCount()
        settings.beginGroup(group)
        try:
            for i in range(cols):
                settings.setValue(f"w{i}", header.sectionSize(i))
        finally:
            settings.endGroup()

    def restore_column_widths(self, settings: QSettings, group: str = "taskTable"):
        header = self.table.horizontalHeader()
        if not header:
            return
        cols = self.table.columnCount()
        settings.beginGroup(group)
        try:
            for i in range(cols):
                val = settings.value(f"w{i}")
                if val is not None:
                    try:
                        header.resizeSection(i, int(val))
                    except Exception:
                        pass
        finally:
            settings.endGroup()

    def bind_header_resize_autosave(self, settings: QSettings, group: str = "taskTable"):
        header = self.table.horizontalHeader()
        if not header:
            return
        header.sectionResized.connect(lambda *_: self.save_column_widths(settings, group))

    # ---------- Первичная настройка таблицы ----------
    def _setup_table_base(self):
        t = self.table
        t.setSortingEnabled(False)  # включим позже, когда убедимся в стабильности
        # Стандартная политика размеров
        header = t.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(True)

        # Кэш колоночных индексов (по заголовку)
        self._rebuild_col_cache()

    def _rebuild_col_cache(self):
        self._col_index_cache.clear()
        t = self.table
        cols = t.columnCount()
        for i in range(cols):
            item = t.horizontalHeaderItem(i)
            name = (item.text().strip() if item else f"Col{i}")
            self._col_index_cache[name] = i

    # ---------- Колонки ----------
    def col(self, name: str) -> int:
        """Безопасно получить индекс колонки по имени заголовка."""
        if name in self._col_index_cache:
            return self._col_index_cache[name]
        # Перестроим кэш на случай, если заголовки изменили
        self._rebuild_col_cache()
        return self._col_index_cache.get(name, 0)

    # ---------- Общие утилиты ----------
    def ensure_item(self, row: int, col: int) -> QTableWidgetItem:
        t = self.table
        item = t.item(row, col)
        if item is None:
            item = QTableWidgetItem()
            t.setItem(row, col, item)
        return item

    def selected_rows(self) -> List[int]:
        """Возвращает уникальные индексы выбранных строк (по выделенным item’ам)."""
        rows = {idx.row() for idx in self.table.selectedIndexes()}
        return sorted(rows)

    # ---------- task_id storage ----------
    def set_row_task_id(self, row: int, task_id: str):
        it = self.ensure_item(row, Col.URL)
        it.setData(ROLE_TASK_ID, task_id)

    def task_id_by_row(self, row: int) -> str | None:
        item = self.table.item(row, Col.URL)
        if not item:
            return None
        val = item.data(ROLE_TASK_ID)
        if isinstance(val, str) and val:
            return val
        # 🔁 fallback для старых строк (миграция на лету)
        legacy = item.data(Qt.UserRole)
        if isinstance(legacy, str) and legacy:
            item.setData(ROLE_TASK_ID, legacy)   # мигрируем сразу
            return legacy
        return None

    def row_by_task_id(self, task_id: str) -> int:
        t = self.table
        for row in range(t.rowCount()):
            item = t.item(row, Col.URL)
            if item and item.data(ROLE_TASK_ID) == task_id:
                return row
        return -1

    # ---------- Сеттеры ячеек ----------
    def set_url_cell(self, row: int, url: str, title: str | None = None, task_id: str | None = None):
        it = self.ensure_item(row, Col.URL)
        it.setText(url or "")
        if title:
            it.setToolTip(title)
        if task_id:
            # пишем в оба слота (новый и старый) для совместимости
            it.setData(ROLE_TASK_ID, task_id)
            it.setData(Qt.UserRole, task_id)

    def set_status_cell(self, row: int, status: str):
        it = self.ensure_item(row, Col.Status)
        it.setText(status or "")

    def set_code_cell(self, row: int, code: Optional[int]):
        it = self.ensure_item(row, Col.Code)
        it.setText("" if code is None else str(code))

    def set_time_cell(self, row: int, ms: Optional[int]):
        it = self.ensure_item(row, Col.Time)
        it.setText("" if ms is None else f"{ms} ms")

    def set_results_cell(self, row: int, summary: str, payload_short: Optional[str] = None):
        it = self.ensure_item(row, Col.Results)
        it.setText(summary or "")
        if payload_short: it.setToolTip(payload_short)

    def set_cookies_cell(self, row: int, has: bool, tip: str = ""):
        it = self.ensure_item(row, Col.Cookies)
        it.setText("Yes" if has else "No")
        if tip:
            it.setToolTip(tip)

    def set_params_cell(self, row: int, text: str):
        it = self.ensure_item(row, Col.Params)
        it.setText(text or "")

    # ---------- Разное ----------
    def ensure_row_visible(self, row: int):
        self.table.scrollToItem(self.ensure_item(row, 0))
