# ui/panels/scraper_tab.py
from __future__ import annotations
from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import QWidget, QTableWidgetItem, QAbstractItemView, QHeaderView

from .scraper_panel_ui import Ui_scraper_panel
from core.scraper.task_manager import TaskManager
from core.scraper.task_types import TaskStatus


class ScraperTabController(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        # 1) Поднимаем UI
        self.ui = Ui_scraper_panel()
        self.ui.setupUi(self)

        # 2) Менеджер задач + индексы строк
        self.task_manager = TaskManager()
        self._row_by_task_id = {}

        # 3) Сигналы менеджера -> контроллер
        self.task_manager.task_log.connect(self.on_task_log)
        self.task_manager.task_status.connect(self.on_task_status)
        self.task_manager.task_progress.connect(self.on_task_progress)
        self.task_manager.task_result.connect(self.on_task_result)
        self.task_manager.task_error.connect(self.on_task_error)

        # 4) Инициализация таблицы
        table = self.ui.taskTable
        table.setColumnCount(2)  # пока: URL | Status
        table.setHorizontalHeaderLabels(["URL", "Status"])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(False)

        # 👉 Автоподгон размеров
        hh: QHeaderView = table.horizontalHeader()
        vh: QHeaderView = table.verticalHeader()
        # колонки по содержимому
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # URL
        hh.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Status
        # последняя колонка заполняет остаток (чтоб красиво тянулась)
        hh.setStretchLastSection(True)
        # строки по содержимому
        vh.setSectionResizeMode(QHeaderView.ResizeToContents)

        # 5) Демонстрационные задачи
        self.add_task_row("https://example.com")
        self.add_task_row("https://cnn.com")
        self.add_task_row("https://github.com")

        # 6) Кнопки — подключаем явно
        assert hasattr(self.ui, "btnStart"), "В .ui нет кнопки btnStart"
        assert hasattr(self.ui, "btnStop"), "В .ui нет кнопки btnStop"
        assert hasattr(self.ui, "btnExport"), "В .ui нет кнопки btnExport"

        # снимаем возможные старые коннекты (на случай повторной инициализации)
        for btn in (self.ui.btnStart, self.ui.btnStop, self.ui.btnExport):
            try:
                btn.clicked.disconnect()
            except Exception:
                pass

        self.ui.btnStart.clicked.connect(self.on_start_clicked)
        self.ui.btnStop.clicked.connect(self.on_stop_clicked)
        self.ui.btnExport.clicked.connect(self.on_export_clicked)

    # ---------- Таблица и строки ----------
    def add_task_row(self, url: str, params: dict | None = None) -> None:
        task_id = self.task_manager.create_task(url, params or {})

        row = self.ui.taskTable.rowCount()
        self.ui.taskTable.insertRow(row)

        # URL
        url_item = QTableWidgetItem(url)
        url_item.setData(Qt.UserRole, task_id)  # сохраняем task_id
        self.ui.taskTable.setItem(row, 0, url_item)

        # Status
        status_item = QTableWidgetItem(TaskStatus.PENDING.value)
        self.ui.taskTable.setItem(row, 1, status_item)

        self._row_by_task_id[task_id] = row

        # поджать размеры сразу
        self.ui.taskTable.resizeRowToContents(row)
        self.ui.taskTable.resizeColumnToContents(0)
        self.ui.taskTable.resizeColumnToContents(1)

    def _find_row_by_task_id(self, task_id: str) -> int:
        return self._row_by_task_id.get(task_id, -1)

    def _set_status_text(self, row: int, text: str) -> None:
        if row < 0:
            return
        item = self.ui.taskTable.item(row, 1)
        if item:
            item.setText(text)
            # обновить размеры под новое содержимое
            self.ui.taskTable.resizeRowToContents(row)
            self.ui.taskTable.resizeColumnToContents(1)

    # ---------- Слоты кнопок ----------
    @Slot()
    def on_start_clicked(self):
        self.append_log_line("[UI] Start clicked")
        self.task_manager.start_all()

    @Slot()
    def on_stop_clicked(self):
        self.append_log_line("[UI] Stop clicked")
        self.task_manager.stop_all()

    @Slot()
    def on_export_clicked(self):
        self.append_log_line("[UI] Export clicked (stub)")

    # ---------- Обработчики сигналов менеджера ----------
    @Slot(str, str, str)
    def on_task_log(self, task_id: str, level: str, text: str):
        self.append_log_line(f"[{level}][{task_id[:8]}] {text}")

    @Slot(str, str)
    def on_task_status(self, task_id: str, status_str: str):
        row = self._find_row_by_task_id(task_id)
        self._set_status_text(row, status_str)

    @Slot(str, int)
    def on_task_progress(self, task_id: str, value: int):
        row = self._find_row_by_task_id(task_id)
        if row >= 0:
            current = self.ui.taskTable.item(row, 1).text() or "Running"
            base = current.split()[0]
            self._set_status_text(row, f"{base} {value}%")

    @Slot(str, dict)
    def on_task_result(self, task_id: str, payload: dict):
        self.append_log_line(f"[RESULT][{task_id[:8]}] {payload}")

    @Slot(str, str)
    def on_task_error(self, task_id: str, error_str: str):
        self.append_log_line(f"[ERROR][{task_id[:8]}] {error_str}")

    # ---------- Логи ----------
    def append_log_line(self, text: str) -> None:
        self.ui.logOutput.appendPlainText(text)
        # автоскролл
        sb = self.ui.logOutput.verticalScrollBar()
        sb.setValue(sb.maximum())
