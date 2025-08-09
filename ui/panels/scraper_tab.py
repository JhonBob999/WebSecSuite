# ui/panels/scraper_tab.py
from __future__ import annotations  # ← должен быть первым
from datetime import datetime
from pathlib import Path
import os
from PySide6.QtCore import Qt, Slot, QSettings, QUrl
from PySide6.QtGui import QTextCursor, QSyntaxHighlighter, QTextCharFormat, QColor, QFont , QDesktopServices
from PySide6.QtWidgets import QWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QDialog, QMenu, QFileDialog, QInputDialog, QWidgetAction

from .scraper_panel_ui import Ui_scraper_panel
from core.scraper.task_manager import TaskManager
from core.scraper import exporter
from core.scraper.task_types import TaskStatus
from dialogs.add_task_dialog import AddTaskDialog

# --- индексы колонок (оставляем твой минимализм) ---
COL_URL     = 0
COL_STATUS  = 1
COL_CODE    = 2
COL_TIME    = 3
COL_RESULT  = 4

# --- палитра ---
CLR_STATUS = {
    "Running": QColor("#4aa3ff"),  # синий
    "Done":    QColor("#2ecc71"),  # зелёный
    "Failed":  QColor("#e74c3c"),  # красный
    "Stopped": QColor("#95a5a6"),  # серый
    "Pending": QColor("#bdc3c7"),  # светло-серый
    "Paused":  QColor("#f1c40f"),  # жёлтый
}
def code_color(http_code: int) -> QColor:
    if 200 <= http_code < 300:
        return QColor("#2ecc71")  # 2xx зелёный
    if 300 <= http_code < 400:
        return QColor("#f1c40f")  # 3xx жёлтый
    return QColor("#e74c3c")      # 4xx/5xx красный и всё прочее

def code_text(http_code: int) -> str:
    # короткая расшифровка; при желании расширим
    common = {
        200: "OK", 301: "Moved Permanently", 302: "Found",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 500: "Internal Server Error", 502: "Bad Gateway",
        503: "Service Unavailable",
    }
    return common.get(int(http_code), "")


#Класс Хайлайтер
class LogHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        # Форматы
        self.f_info = QTextCharFormat()
        self.f_info.setForeground(QColor("#A0A0A0"))  # мягкий серый

        self.f_warn = QTextCharFormat()
        self.f_warn.setForeground(QColor("#C8A200"))  # жёлто-янтарный
        self.f_warn.setFontWeight(QFont.Bold)

        self.f_error = QTextCharFormat()
        self.f_error.setForeground(QColor("#E05A5A"))  # красный
        self.f_error.setFontWeight(QFont.Bold)

        self.f_result = QTextCharFormat()
        self.f_result.setForeground(QColor("#3CC3D3"))  # бирюзовый
        self.f_result.setFontWeight(QFont.DemiBold)

        self.f_taskid = QTextCharFormat()
        self.f_taskid.setForeground(QColor("#808080"))  # серый для [abcd1234]

    def highlightBlock(self, text: str):
        # Уровни
        if "] [ERROR]" in text:
            self.setFormat(0, len(text), self.f_error)
        elif "] [WARN]" in text:
            self.setFormat(0, len(text), self.f_warn)
        elif "] [RESULT]" in text:
            self.setFormat(0, len(text), self.f_result)
        elif "] [INFO]" in text:
            self.setFormat(0, len(text), self.f_info)

        # Подсветим короткий task_id вида [e0f1a2b3]
        # (пробегаем и находим такие подпоследовательности)
        start = 0
        while True:
            i = text.find("[", start)
            if i < 0:
                break
            j = text.find("]", i + 1)
            if j < 0:
                break
            token = text[i:j+1]
            # [abcdef12] — восьмизначный hex?
            if len(token) == 10 and all(c in "0123456789abcdef" for c in token[1:-1].lower()):
                self.setFormat(i, j - i + 1, self.f_taskid)
            start = j + 1


class ScraperTabController(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        # 1) Поднимаем UI
        self.ui = Ui_scraper_panel()
        self.ui.setupUi(self)
        
        # Хайлайтер подключение
        self._log_hl = LogHighlighter(self.ui.logOutput.document())
        # Подключение настроек таблиц
        self.settings = QSettings("WebSecSuite", "WebSecSuite")  # имя можешь поменять
        self._setup_task_table()
        self._restore_table_state()
        
        # двойной клик
        self.ui.taskTable.cellDoubleClicked.connect(self.on_task_cell_double_clicked)
        # сохраняем ширины на лету
        hdr = self.ui.taskTable.horizontalHeader()
        hdr.sectionResized.connect(self._save_table_state)
        
        
        # 2) Менеджер задач + индексы строк
        self.task_manager = TaskManager()
        self._row_by_task_id = {}

        # 3) Сигналы менеджера -> контроллер
        self.task_manager.task_log.connect(self.on_task_log)
        self.task_manager.task_status.connect(self.on_task_status)
        self.task_manager.task_progress.connect(self.on_task_progress)
        self.task_manager.task_result.connect(self.on_task_result)
        self.task_manager.task_error.connect(self.on_task_error)
        self.task_manager.task_reset.connect(self._on_task_reset)
        self.task_manager.task_restarted.connect(self._on_task_restarted)

        # 4) Инициализация таблицы
        table = self.ui.taskTable
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.ui.taskTable.setSelectionMode(QAbstractItemView.ExtendedSelection)
        table.setAlternatingRowColors(True)

        # контекстное меню
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(self.on_context_menu)

        # 👉 Автоподгон размеров
        hh: QHeaderView = table.horizontalHeader()
        vh: QHeaderView = table.verticalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # URL
        hh.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Status
        hh.setStretchLastSection(True)
        vh.setSectionResizeMode(QHeaderView.ResizeToContents)

        # 5) Демонстрационные задачи
        self.add_task_row("https://delfi.lv")
        self.add_task_row("https://cnn.com")
        self.add_task_row("https://github.com")

        # 6) Кнопки — подключаем явно
        assert hasattr(self.ui, "btnStart"), "В .ui нет кнопки btnStart"
        assert hasattr(self.ui, "btnStop"), "В .ui нет кнопки btnStop"
        assert hasattr(self.ui, "btnExport"), "В .ui нет кнопки btnExport"
        assert hasattr(self.ui, "btnAddTask"), "В .ui нет кнопки btnAddTask"

        self.ui.btnAddTask.clicked.connect(self.on_add_task_clicked)
        self.ui.btnStart.clicked.connect(self.on_start_clicked)
        self.ui.btnStop.clicked.connect(self.on_stop_clicked)
        self.ui.btnExport.clicked.connect(self.on_export_clicked)
        self.ui.btnDelete.clicked.connect(self.on_delete_clicked)

        # ▼▼▼ ЛОГ-БУФЕР И ФИЛЬТР (п.2 из next_step)
        self.log_buffer = []                  # list[tuple[str, str, str]]: (ts, level, text)
        self.log_filter = {"INFO", "WARN", "ERROR"}
        self.MAX_LOG_LINES = 5000

        self._init_ui_connections()

    # ---------- ИНИЦИАЛИЗАЦИЯ КНОПОК ФИЛЬТРОВ ----------
    def _init_ui_connections(self):
        # Кнопки фильтров (toggle)
        if hasattr(self.ui, "btnInfo"):
            self.ui.btnInfo.toggled.connect(lambda checked: self._toggle_level("INFO", checked))
        if hasattr(self.ui, "btnWarn"):
            self.ui.btnWarn.toggled.connect(lambda checked: self._toggle_level("WARN", checked))
        if hasattr(self.ui, "btnError"):
            self.ui.btnError.toggled.connect(lambda checked: self._toggle_level("ERROR", checked))
        # Clear — очищает экран, но НЕ буфер
        if hasattr(self.ui, "btnClearLog"):
            self.ui.btnClearLog.clicked.connect(self._clear_log_screen)
            
     # --- настройка таблицы, один раз ---
    def _setup_task_table(self):
        t = self.ui.taskTable
        t.setColumnCount(5)
        t.setHorizontalHeaderLabels(["URL", "Status", "Code", "Time", "Results"])

        # выбор строк
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.setSelectionMode(QAbstractItemView.ExtendedSelection)

        # сортировка и растягивание
        t.setSortingEnabled(True)
        t.horizontalHeader().setStretchLastSection(True)

    # --- сохранение/восстановление ширин ---
    def _save_table_state(self):
        hdr = self.ui.taskTable.horizontalHeader()
        widths = [hdr.sectionSize(i) for i in range(self.ui.taskTable.columnCount())]
        self.settings.setValue("scraper/table_widths", widths)

    def _restore_table_state(self):
        widths = self.settings.value("scraper/table_widths")
        if widths:
            try:
                widths = list(map(int, widths))
                for i, w in enumerate(widths):
                    self.ui.taskTable.setColumnWidth(i, w)
            except Exception:
                pass
            
    # --- удобные сеттеры ячеек ---
    def _ensure_item(self, row: int, col: int) -> QTableWidgetItem:
        t = self.ui.taskTable
        it = t.item(row, col)
        if it is None:
            it = QTableWidgetItem("")
            it.setFlags(it.flags() ^ Qt.ItemIsEditable)  # запрет редактирования
            t.setItem(row, col, it)
        return it

    def set_url_cell(self, row: int, url: str, page_title: str | None = None):
        it = self._ensure_item(row, COL_URL)
        it.setText(self._shorten_url(url))
        tip = url if not page_title else f"{url}\nTitle: {page_title}"
        it.setToolTip(tip)

    def set_status_cell(self, row: int, status: str):
        it = self._ensure_item(row, COL_STATUS)
        it.setText(status)
        color = CLR_STATUS.get(status.split()[0], QColor("#bdc3c7"))
        it.setData(Qt.ForegroundRole, color)
        font = it.font()
        font.setBold(status.startswith(("Running", "Failed")))
        it.setFont(font)
        it.setToolTip(status)

    def set_code_cell(self, row: int, code: int | str | None):
        it = self._ensure_item(row, COL_CODE)
        if code in (None, ""):
            it.setText(""); it.setToolTip(""); it.setData(Qt.ForegroundRole, None)
            return
        try:
            code_i = int(code)
        except Exception:
            code_i = 0
        it.setText(str(code_i))
        it.setData(Qt.ForegroundRole, code_color(code_i))
        it.setToolTip(f"{code_i} {code_text(code_i)}".strip())

    def set_time_cell(self, row: int, elapsed_ms: float | int | None):
        it = self._ensure_item(row, COL_TIME)
        if elapsed_ms is None:
            it.setText(""); it.setToolTip(""); return
        ms = float(elapsed_ms)
        text = f"{int(ms)} ms" if ms < 1000 else f"{ms/1000:.2f} s"
        it.setText(text)
        it.setToolTip(f"Elapsed: {int(ms)} ms")

    def set_result_cell(self, row: int, path_or_flag: str | None):
        it = self._ensure_item(row, COL_RESULT)
        if not path_or_flag:
            it.setText(""); it.setToolTip(""); return
        p = str(path_or_flag)
        it.setText(Path(p).name)
        it.setToolTip(p)

    # --- двойные клики: URL/Result ---
    def on_task_cell_double_clicked(self, row: int, col: int):
        try:
            if col == COL_URL:
                url_item = self.ui.taskTable.item(row, COL_URL)
                if not url_item:
                    return
                tip = url_item.toolTip() or url_item.text()
                full_url = tip.split("\n")[0]
                if full_url.startswith("http"):
                    QDesktopServices.openUrl(QUrl(full_url))
            elif col == COL_RESULT:
                res_item = self.ui.taskTable.item(row, COL_RESULT)
                if not res_item:
                    return
                path = res_item.toolTip() or res_item.text()
                if path:
                    self._open_path(path)
        except Exception:
            pass

    # --- утилиты ---
    def _open_path(self, path: str):
        p = Path(path)
        if not p.exists():
            p = p.parent
        try:
            if os.name == "nt":
                os.startfile(str(p))    # type: ignore
            elif sys.platform == "darwin":
                os.system(f'open "{p}"')
            else:
                os.system(f'xdg-open "{p}"')
        except Exception:
            pass

    def _shorten_url(self, url: str, max_len: int = 60) -> str:
        if len(url) <= max_len:
            return url
        return f"{url[:30]}…{url[-20:]}"

    def _toggle_level(self, level: str, enabled: bool):
        level = level.upper()
        if enabled:
            self.log_filter.add(level)
        else:
            self.log_filter.discard(level)
        self.refresh_log_view()

    def _clear_log_screen(self):
        if hasattr(self.ui, "logOutput"):
            self.ui.logOutput.clear()

    def refresh_log_view(self):
        """Перерисовать logOutput из буфера с учётом фильтра."""
        if not hasattr(self.ui, "logOutput"):
            return
        lines = []
        for ts, level, text in self.log_buffer:
            if level in self.log_filter:
                lines.append(f"[{ts}] [{level}] {text}")
        self.ui.logOutput.setPlainText("\n".join(lines))
        sb = self.ui.logOutput.verticalScrollBar()
        sb.setValue(sb.maximum())

    def append_log(self, level: str, text: str):
        """Единая точка входа: добавить строку в буфер и (если видно) на экран."""
        level = (level or "INFO").upper()
        if level not in {"INFO", "WARN", "ERROR"}:
            level = "INFO"
        ts = datetime.now().strftime("%H:%M:%S")

        self.log_buffer.append((ts, level, str(text)))
        # Ограничиваем размер буфера
        if len(self.log_buffer) > self.MAX_LOG_LINES:
            del self.log_buffer[:1000]

        # Если уровень включен — дописываем инкрементально
        if hasattr(self.ui, "logOutput") and level in self.log_filter:
            cursor = self.ui.logOutput.textCursor()
            cursor.movePosition(QTextCursor.End)
            cursor.insertText(f"[{ts}] [{level}] {text}\n")
            self.ui.logOutput.setTextCursor(cursor)
            self.ui.logOutput.ensureCursorVisible()

    # Обратная совместимость: старые вызовы self.append_log_line("...") с префиксами
    def append_log_line(self, text: str) -> None:
        """
        Поддерживает текущие вызовы вида:
          "[WARN] ..." / "[ERROR] ..." / "[INFO] ..." / "[UI] ..."
        Извлекает уровень, остальное — как текст.
        """
        raw = str(text or "")
        lvl = "INFO"
        if raw.startswith("[WARN]"):
            lvl, raw = "WARN", raw[6:].lstrip()
        elif raw.startswith("[ERROR]"):
            lvl, raw = "ERROR", raw[7:].lstrip()
        elif raw.startswith("[INFO]"):
            lvl, raw = "INFO", raw[6:].lstrip()
        else:
            # special tags типа [UI], [RESULT] — оставим как INFO
            pass
        self.append_log(lvl, raw)

    # ---------- Таблица и строки ----------
    def add_task_row(self, url: str, params: dict | None = None) -> None:
        task_id = self.task_manager.create_task(url, params or {})

        row = self.ui.taskTable.rowCount()
        self.ui.taskTable.insertRow(row)

        # сохраняем task_id в URL-ячейку
        url_item = QTableWidgetItem("")  # текст поставим через set_url_cell
        url_item.setData(Qt.UserRole, task_id)
        self.ui.taskTable.setItem(row, COL_URL, url_item)

        # наполнить ячейки базовыми значениями
        self.set_url_cell(row, url)
        self.set_status_cell(row, TaskStatus.PENDING.value)
        self.set_code_cell(row, None)
        self.set_time_cell(row, None)
        self.set_result_cell(row, None)

        self._row_by_task_id[task_id] = row
        self.ui.taskTable.resizeRowToContents(row)

    # ---------- Хелперы для выделения/ID и батч-операций ----------
    def _selected_rows(self):
        sel = self.ui.taskTable.selectionModel()
        if not sel or not sel.hasSelection():
            return []
        return sorted({idx.row() for idx in sel.selectedRows()})

    def _task_id_by_row(self, row: int) -> str | None:
        it = self.ui.taskTable.item(row, 0)
        return it.data(Qt.UserRole) if it else None

    def start_selected_tasks(self):
        rows = self._selected_rows()
        if not rows:
            self.append_log_line("[WARN] No tasks selected")
            return
        for row in rows:
            task_id = self._task_id_by_row(row)
            if not task_id:
                continue
            try:
                self.task_manager.start_task(task_id)
                self.append_log_line(f"[UI] Start task {task_id[:8]}")
            except Exception as e:
                self.append_log_line(f"[ERROR] start_task({task_id[:8]}): {e}")

    def stop_selected_tasks(self):
        rows = self._selected_rows()
        if not rows:
            self.append_log_line("[WARN] No tasks selected")
            return
        for row in rows:
            task_id = self._task_id_by_row(row)
            if task_id:
                self.task_manager.stop_task(task_id)
        self.append_log_line(f"[UI] Stopped {len(rows)} task(s)")

    def delete_selected_tasks(self):
        self.on_delete_clicked()
        
    def _format_result_short(self, payload: dict) -> str:
        # безопасные get'ы
        url = payload.get("final_url") or payload.get("url") or ""
        code = payload.get("status_code", "")
        title = (payload.get("title") or "").strip()
        size = payload.get("content_len", "")
        timings = payload.get("timings", {}) or {}
        t_req = timings.get("request_ms", "")
        t_total = timings.get("total_ms", "")

        # короткие заголовки
        headers = payload.get("headers", {}) or {}
        hdr_pairs = []
        for k in ("server", "content-type", "content-length", "date", "via", "x-powered-by", "cf-ray"):
            if k in headers or k.title() in headers:
                v = headers.get(k, headers.get(k.title()))
                hdr_pairs.append(f"    {k}: {v}")
        hdr_block = ("\n" + "\n".join(hdr_pairs)) if hdr_pairs else ""

        lines = [
            f"  URL: {url}",
            f"  Status: {code}",
            f"  Title: {title}" if title else "  Title: (none)",
            f"  Size: {size} bytes",
            f"  Time: request {t_req} ms, total {t_total} ms",
        ]
        if hdr_block:
            lines.append("  Headers:" + hdr_block)
        return "\n".join(lines)
    
    def _selected_task_ids(self):
        rows = self._selected_rows()
        ids = []
        for r in rows:
            tid = self._task_id_by_row(r)
            if tid:
                ids.append(tid)
        return ids
    
    # Обновление строки таблицы по task_id
    def _refresh_row_by_task_id(self, task_id: str):
        row = self._find_row_by_task_id(task_id)
        if row < 0:
            return
        task = self.task_manager._tasks.get(task_id)
        if not task:
            return
        self.set_status_cell(row, getattr(task, "status", "") or "")

    def _find_row_by_task_id(self, task_id: str) -> int:
        return self._row_by_task_id.get(task_id, -1)


    def reset_selected_tasks(self):
        ids = self._selected_task_ids()
        if not ids:
            self.append_log_line("[WARN] No rows selected for reset.")
            return
        ok = 0
        for tid in ids:
            if self.task_manager.reset_task(tid):
                ok += 1
                self._refresh_row_by_task_id(tid)
                self.append_log_line(f"[INFO] Task {tid} reset")
        self.append_log_line(f"[INFO] Reset done: {ok}/{len(ids)}")

    def restart_selected_tasks(self):
        ids = self._selected_task_ids()
        if not ids:
            self.append_log_line("[WARN] No rows selected for restart.")
            return
        ok = 0
        for tid in ids:
            if self.task_manager.restart_task(tid):
                ok += 1
                self.append_log_line(f"[INFO] Task {tid} restarted")
        self.append_log_line(f"[INFO] Restart done: {ok}/{len(ids)}")
        
    def _on_task_reset(self, task_id):
        self._refresh_row_by_task_id(task_id)
        
    def _on_task_restarted(self, task_id: str):
        # можно ничего не делать: воркер сам будет пушить прогресс/статус
        pass

    # --------------- Ячейки таблици -----------------
        
        



    # ---------- Контекстное меню ----------
    def on_context_menu(self, pos):
        table = self.ui.taskTable
        global_pos = table.viewport().mapToGlobal(pos)

        row_under_cursor = table.rowAt(pos.y())
        if row_under_cursor >= 0:
            if row_under_cursor not in self._selected_rows():
                table.clearSelection()
                table.selectRow(row_under_cursor)

        has_selection = len(self._selected_rows()) > 0

        menu = QMenu(self)

        act_start   = menu.addAction("Start selected")
        act_stop    = menu.addAction("Stop selected")
        act_del     = menu.addAction("Delete selected")
        menu.addSeparator()
        # ↓ добавляем новые пункты
        act_reset   = menu.addAction("Reset selected")
        act_restart = menu.addAction("Restart selected")
        menu.addSeparator()
        act_add     = menu.addAction("Add task")

        # доступность по выбору
        for a in (act_start, act_stop, act_del, act_reset, act_restart):
            a.setEnabled(has_selection)

        # PyQt5 обычно menu.exec_(...), PySide6 — menu.exec(...). Оставь как у тебя работает.
        action = menu.exec(global_pos)
        if action is None:
            return

        if action == act_start:
            self.start_selected_tasks()
        elif action == act_stop:
            self.stop_selected_tasks()
        elif action == act_del:
            self.delete_selected_tasks()
        elif action == act_reset:
            self.reset_selected_tasks()
        elif action == act_restart:
            self.restart_selected_tasks()
        elif action == act_add:
            self.on_add_task_clicked()

    # ---------- Слоты кнопок ----------
    @Slot()
    def on_start_clicked(self):
        table = self.ui.taskTable
        sel = table.selectionModel()

        if not sel or not sel.hasSelection():
            self.append_log_line("[WARN] No tasks selected")
            return

        rows = sorted({idx.row() for idx in sel.selectedRows()})
        if not rows:
            self.append_log_line("[WARN] No valid rows selected")
            return

        for row in rows:
            item = table.item(row, 0)  # колонка URL
            if not item:
                continue
            task_id = item.data(Qt.UserRole)
            if task_id:
                try:
                    self.task_manager.start_task(task_id)
                    self.append_log_line(f"[UI] Start task {task_id[:8]}")
                except Exception as e:
                    self.append_log_line(f"[ERROR] start_task({task_id[:8]}): {e}")

    @Slot()
    def on_stop_clicked(self):
        self.append_log_line("[UI] Stop clicked")
        self.task_manager.stop_all()

    @Slot()
    def on_export_clicked(self):
        # 1) Выбор Scope
        scopes = ["Selected", "Completed", "All"]
        scope, ok = QInputDialog.getItem(self, "Export scope", "Choose:", scopes, 0, False)
        if not ok:
            return

        # 2) Формат — спросим через стандартный диалог
        filters = "CSV (*.csv);;Excel (*.xlsx);;JSON (*.json)"

        # Папка по умолчанию (data/exports) или последняя использованная
        settings = QSettings("WebSecSuite", "Scraper")
        last_dir = settings.value("export/last_dir", "", str) or exporter.default_exports_dir()

        # Предложим осмысленное имя
        default_fmt = "csv"
        suggested_name = exporter.suggest_filename(default_fmt, scope)
        start_path = os.path.join(last_dir, suggested_name)

        path, selected_filter = QFileDialog.getSaveFileName(self, "Export tasks", start_path, filters)
        if not path:
            return

        # Определим fmt по расширению/фильтру
        lf = path.lower()
        if lf.endswith(".csv"):
            fmt = "csv"
        elif lf.endswith(".xlsx"):
            fmt = "xlsx"
        elif lf.endswith(".json"):
            fmt = "json"
        else:
            if "CSV" in selected_filter:
                fmt = "csv"; path += ".csv"
            elif "Excel" in selected_filter:
                fmt = "xlsx"; path += ".xlsx"
            else:
                fmt = "json"; path += ".json"

        # 3) Соберём задачи
        tasks = []
        try:
            if scope == "Selected":
                rows = self._selected_rows()
                if not rows:
                    self.append_log_line("[WARN] Nothing selected for export")
                    return
                for r in rows:
                    tid = self._task_id_by_row(r)
                    t = self.task_manager.get_task(tid)
                    if t: tasks.append(t)
            elif scope == "Completed":
                for t in self.task_manager.get_all_tasks():
                    if getattr(t, "status", None) == TaskStatus.DONE:
                        tasks.append(t)
            else:
                tasks = self.task_manager.get_all_tasks()

            if not tasks:
                self.append_log_line("[WARN] No tasks to export")
                return

            # 4) Экспорт
            out = exporter.export_tasks(tasks, fmt, path)
            self.append_log_line(f"[INFO] Exported {len(tasks)} task(s) → {out}")

            # запомним папку
            settings.setValue("export/last_dir", os.path.dirname(out))

        except Exception as e:
            self.append_log_line(f"[ERROR] Export failed: {e}")


    @Slot()
    def on_add_task_clicked(self):
        dlg = AddTaskDialog(self)  # наше модальное окно
        if dlg.exec() == QDialog.Accepted and dlg.data:
            data = dlg.data
            self.add_task_row(data["url"], params=data)
            self.append_log_line(f"[INFO] Added task → {data['url']}")

    @Slot()
    def on_delete_clicked(self):
        table = self.ui.taskTable
        sel = table.selectionModel()
        if not sel or not sel.hasSelection():
            self.append_log_line("[WARN] Select a row to delete")
            return

        rows = sorted({idx.row() for idx in sel.selectedRows()}, reverse=True)

        for row in rows:
            item = table.item(row, 0)  # колонка с URL и UserRole=task_id
            if not item:
                continue
            task_id = item.data(Qt.UserRole)
            if task_id:
                try:
                    self.task_manager.remove_task(task_id)
                except Exception as e:
                    self.append_log_line(f"[ERROR] remove_task({task_id[:8]}): {e}")
            table.removeRow(row)

        self._rebuild_row_index_map()
        self.append_log_line(f"[INFO] Deleted {len(rows)} task(s)")

    # ---------- Пересборка индексов ----------
    def _rebuild_row_index_map(self):
        self._row_by_task_id.clear()
        for row in range(self.ui.taskTable.rowCount()):
            it = self.ui.taskTable.item(row, 0)
            if not it:
                continue
            task_id = it.data(Qt.UserRole)
            if task_id:
                self._row_by_task_id[task_id] = row

    # ---------- Обработчики сигналов менеджера ----------
    @Slot(str, str, str)
    def on_task_log(self, task_id: str, level: str, text: str):
        # уровень идёт отдельным аргументом → используем его как фильтр
        self.append_log(level, f"[{task_id[:8]}] {text}")

    @Slot(str, str)
    def on_task_status(self, task_id: str, status_str: str):
        row = self._find_row_by_task_id(task_id)
        if row >= 0:
            self.set_status_cell(row, status_str)

    @Slot(str, int)
    def on_task_progress(self, task_id: str, value: int):
        row = self._find_row_by_task_id(task_id)
        if row >= 0:
            base = "Running"
            st_item = self.ui.taskTable.item(row, COL_STATUS)
            if st_item and st_item.text():
                base = st_item.text().split()[0]
            self.set_status_cell(row, f"{base} {value}%")

    @Slot(str, dict)
    def on_task_result(self, task_id: str, payload: dict):
        # в лог — кратко и красиво
        pretty = self._format_result_short(payload)
        self.append_log_line(f"[RESULT][{task_id[:8]}]\n{pretty}")
        # (полный payload уже хранится в task.result / приходит из воркера — оставляем как есть)
        # обновим таблицу
        row = self._find_row_by_task_id(task_id)
        if row >= 0:
            self.set_status_cell(row, "Done")
            self.set_url_cell(row, payload.get("final_url") or payload.get("url") or "", payload.get("title"))
            self.set_code_cell(row, payload.get("status_code"))
            # elapsed_ms / total_ms — как у тебя называется в payload
            elapsed = payload.get("elapsed_ms") or (payload.get("timings") or {}).get("total_ms")
            self.set_time_cell(row, elapsed)
            self.set_result_cell(row, payload.get("result_path"))


    @Slot(str, str)
    def on_task_error(self, task_id: str, error_str: str):
        self.append_log_line(f"[ERROR][{task_id[:8]}] {error_str}")
