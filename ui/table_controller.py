# ui/table_controller.py
from __future__ import annotations
from ui.constants import Col
from typing import Optional, Iterable, Dict, List, Tuple
from PySide6.QtCore import Qt, QSettings, QPoint
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView, QMenu
from PySide6.QtGui import QAction

import json

SETTINGS_KEY = "ui/taskTable/widths_v2"

DEFAULT_WIDTHS = {
    Col.URL:     260,
    Col.Status:   90,
    Col.Code:     70,
    Col.Time:     90,
    Col.Results: 520,
    Col.Cookies:  80,
    Col.Params:  120,
}
ROLE_TASK_ID = Qt.UserRole + 1

class TaskTableController:
    def __init__(self, table: QTableWidget):
        self.table = table
        self._col_index_cache: Dict[str, int] = {}
        self._setup_table_base()
        hh = table.horizontalHeader()
        
         # 1) Ручная регулировка, НИКАКОГО ResizeToContents глобально
        hh.setSectionResizeMode(QHeaderView.Interactive)
        hh.setStretchLastSection(False)
        hh.setHighlightSections(False)
        hh.setSectionsMovable(False)   # если не нужно перетаскивание
        hh.setCascadingSectionResizes(False)

        # 2) Контекст-меню хедера: добавим Reset
        hh.setContextMenuPolicy(Qt.CustomContextMenu)
        hh.customContextMenuRequested.connect(self._on_header_menu)

        # 3) Двойной клик по разделителю → авто-подогнать только одну колонку
        hh.sectionHandleDoubleClicked.connect(self._on_handle_double_click)

        # 4) Восстановить ширины (или выставить дефолты)
        if not self.restore_column_widths():
            self.apply_default_widths()

        # 5) Сохранять при каждом изменении
        hh.sectionResized.connect(lambda *_: self.save_column_widths())
        
        self._init_header_tooltips()
        
        
    def apply_common_view_settings(self):
        t = self.table
        t.verticalHeader().setVisible(False)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.setSelectionMode(QAbstractItemView.ExtendedSelection)
        t.setAlternatingRowColors(True)
        
        # ---------- Политики размеров ----------
    def setup_resize_policies(self):
        t = self.table
        hh = t.horizontalHeader()
        vh = t.verticalHeader()

        # ширина колонок — руками
        hh.setSectionResizeMode(QHeaderView.Interactive)
        hh.setStretchLastSection(False)

        # ВАЖНО: высота строк — НЕ Auto, а руками
        vh.setSectionResizeMode(QHeaderView.Interactive)   # можно тянуть мышью
        vh.setDefaultSectionSize(26)                       # дефолтная высота (подбери 24–28)

        # чтобы длинный текст не «принуждал» к росту строки из-за переноса
        t.setWordWrap(False)



    # ---------- Widths ----------

    def apply_default_widths(self):
        for col, w in DEFAULT_WIDTHS.items():
            if 0 <= col < self.table.columnCount():
                self.table.setColumnWidth(int(col), int(w))

    def save_column_widths(self):
        try:
            widths = [self.table.columnWidth(i) for i in range(self.table.columnCount())]
            QSettings().setValue(SETTINGS_KEY, widths)
        except Exception:
            # не логируем ошибку тут, чтобы не заспамить — «молчаливый» гвард
            pass

    def restore_column_widths(self) -> bool:
        try:
            v = QSettings().value(SETTINGS_KEY, None)
            if not v:
                return False
            widths = list(map(int, v))
            if len(widths) != self.table.columnCount():
                return False
            for i, w in enumerate(widths):
                self.table.setColumnWidth(i, max(24, w))  # минимум чтобы не схлопывалось
            return True
        except Exception:
            return False

    def reset_column_widths(self):
        self.apply_default_widths()
        self.save_column_widths()

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
            
        # ---------- Header UX ----------

    def _on_handle_double_click(self, logicalIndex: int):
        """Дабл-клик по разделителю → resize только этой секции по содержимому."""
        if 0 <= logicalIndex < self.table.columnCount():
            self.table.resizeColumnToContents(logicalIndex)
            # чуть расширим, чтобы текст не упирался в границу
            self.table.setColumnWidth(logicalIndex, self.table.columnWidth(logicalIndex) + 12)
            self.save_column_widths()

    def _on_header_menu(self, pos: QPoint):
        menu = QMenu(self.table)
        act_reset = QAction("Reset column widths", menu)
        act_reset.triggered.connect(self.reset_column_widths)

        act_autofit_all = QAction("Auto-fit all (once)", menu)
        act_autofit_all.triggered.connect(self._autofit_all_once)

        menu.addAction(act_reset)
        menu.addSeparator()
        menu.addAction(act_autofit_all)
        menu.exec(self.table.horizontalHeader().mapToGlobal(pos))

    def _autofit_all_once(self):
        """Разовая операция авто-подгонки всех колонок (без фиксации режима)."""
        # ВАЖНО: не включаем ResizeToContents постоянно, только вызов resizeColumnToContents
        for i in range(self.table.columnCount()):
            self.table.resizeColumnToContents(i)
            self.table.setColumnWidth(i, self.table.columnWidth(i) + 12)
        self.save_column_widths()

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

    def set_results_cell(
        self,
        row: int,
        payload: dict | None = None,       # вариант 1: даём полный payload
        summary: str | None = None,        # вариант 2: даём краткий текст
        payload_short: str | None = None,  # tooltip/короткая версия payload
    ):
        """
        Умеет оба варианта:
          • set_results_cell(row, payload=payload)
          • set_results_cell(row, summary="200 · 12KB · 540 ms · r=1", payload_short="<pretty json>")

        Если передан payload — сам соберёт summary и tooltip.
        """
        item = self.ensure_item(row, Col.Results)

        # Вариант 1: передали полноценный payload -> сделаем короткое резюме и tooltip
        if payload is not None:
            code = payload.get("status_code")
            size = payload.get("content_len")
            tms  = (payload.get("timings") or {}).get("request_ms")
            red  = len(payload.get("redirect_chain") or [])
            summary = f"{code} · {size} B · {tms} ms · r={red}"

            try:
                payload_short = json.dumps(payload, ensure_ascii=False, indent=2)
            except Exception:
                payload_short = str(payload)

        # Вариант 2: передали уже готовые summary/payload_short
        text = summary or ""
        tip  = payload_short or ("No results yet" if not text else "")

        item.setText(text)
        item.setData(Qt.TextAlignmentRole, Qt.AlignLeft | Qt.AlignVCenter)
        item.setToolTip(tip)


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
        
        
    def _init_header_tooltips(self):
        """
        Назначает tooltips для заголовков колонок.
        Безопасно создаёт headerItem, если его ещё нет.
        """
        t = self.table

        tips: dict[int, str] = {
            Col.URL:     "Исходный адрес задачи (двойной клик — открыть в браузере)",
            Col.Status:  "Текущий статус задачи (PENDING / RUNNING / DONE / FAILED / STOPPED)",
            Col.Code:    "HTTP-код ответа сервера (последнего запроса)",
            Col.Time:    "Время запроса, мс (timings.request_ms)",
            Col.Results: "Краткое резюме результата; полный JSON — в tooltip ячейки",
            Col.Cookies: "Куки-файл, используемый задачей (авто по домену или кастомный путь)",
            Col.Params:  "Параметры запроса: метод, proxy, headers, user-agent и т.д.",
        }

        for col, tip in tips.items():
            self._ensure_header_item(col)
            item = t.horizontalHeaderItem(col)
            if item:
                item.setToolTip(tip)

    def _ensure_header_item(self, col: int):
        """
        QTableWidget иногда не имеет headerItem по умолчанию, если заголовки заданы через setHorizontalHeaderLabels.
        Создаём QTableWidgetItem при необходимости, не меняя существующий текст заголовка.
        """
        t = self.table
        if 0 <= col < t.columnCount() and t.horizontalHeaderItem(col) is None:
            # берём текущий текст заголовка, если он задан
            header_text = t.model().headerData(col, Qt.Horizontal, Qt.DisplayRole)
            item = QTableWidgetItem(str(header_text) if header_text is not None else "")
            t.setHorizontalHeaderItem(col, item)

