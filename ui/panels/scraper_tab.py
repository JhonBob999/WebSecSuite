# ui/panels/scraper_tab.py
from __future__ import annotations  # ← должен быть первым
from datetime import datetime
from pathlib import Path
from dialogs.params_dialog import ParamsDialog
import os
from PySide6.QtCore import Qt, Slot, QSettings, QUrl, QRegularExpression
from PySide6.QtGui import QTextCursor, QSyntaxHighlighter, QTextCharFormat, QColor, QFont , QDesktopServices, QGuiApplication
from PySide6.QtWidgets import QWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QDialog, QMenu, QFileDialog, QInputDialog, QWidgetAction, QMessageBox

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
COL_COOKIES = 5
COL_PARAMS  = 6

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
        
        self._search_regex = QRegularExpression()
        self._search_fmt = QTextCharFormat()
        self._search_fmt.setBackground(QColor(255, 255, 0, 100))

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
            
        # --- ДОПОЛНИТЕЛЬНАЯ ПОДСВЕТКА ПОИСКА ---
        if hasattr(self, "_search_regex") and self._search_regex.isValid() and self._search_regex.pattern():
            it = self._search_regex.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), self._search_fmt)
            
    def set_pattern(self, text: str, *, regex_mode=False, case_sensitive=False):
        if not text:
            self._search_regex = QRegularExpression()
            self.rehighlight()
            return
        pattern = text if regex_mode else QRegularExpression.escape(text)
        rx = QRegularExpression(pattern)
        rx.setPatternOptions(
            QRegularExpression.NoPatternOption if case_sensitive
            else QRegularExpression.CaseInsensitiveOption
        )
        self._search_regex = rx
        self.rehighlight()


class ScraperTabController(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        # 1) Поднимаем UI
        self.ui = Ui_scraper_panel()
        self.ui.setupUi(self)
        
        # Хайлайтер подключение
        self._log_hl = LogHighlighter(self.ui.logOutput.document())
        # создаём хайлайтер и цепляем к документу логов
        self.ui.lineEditLogFilter.setClearButtonEnabled(True)
        self.ui.lineEditLogFilter.textChanged.connect(self._on_filter_text_changed)
        
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
        self.ui.btnPause.clicked.connect(self.on_pause_clicked)    # ← добавлено
        self.ui.btnResume.clicked.connect(self.on_resume_clicked)  # ← добавлено

        # ▼▼▼ ЛОГ-БУФЕР И ФИЛЬТР (п.2 из next_step)
        self.log_buffer = []                  # list[tuple[str, str, str]]: (ts, level, text)
        self.log_filter = {"INFO", "WARN", "ERROR"}
        self.MAX_LOG_LINES = 5000

        self._init_ui_connections()

    # ---------- ИНИЦИАЛИЗАЦИЯ КНОПОК ФИЛЬТРОВ ----------
    def _init_ui_connections(self):
        # Clear — очищает экран, но НЕ буфер
        if hasattr(self.ui, "btnClearLog"):
            self.ui.btnClearLog.clicked.connect(self._clear_log_screen)
            
            
    def _on_filter_text_changed(self, text: str):
        # базовая версия: без regex и без учёта регистра
        self._log_hl.set_pattern(
            text,
            regex_mode=False,
            case_sensitive=False
        )
            
     # --- настройка таблицы, один раз ---
    def _setup_task_table(self):
        t = self.ui.taskTable
        t.setColumnCount(7)
        t.setHorizontalHeaderLabels(["URL", "Status", "Code", "Time", "Results", "Cookies", "Params"])
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.setSelectionMode(QAbstractItemView.ExtendedSelection)
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
        
    def set_cookies_cell(self, row: int, has_cookies: bool, cookies_tip: str = ""):
        it = self._ensure_item(row, COL_COOKIES)
        it.setText("✔" if has_cookies else "")
        it.setToolTip(cookies_tip or ("Set-Cookie present" if has_cookies else ""))

    def set_params_cell(self, row: int, has_params: bool, params_tip: str = ""):
        it = self._ensure_item(row, COL_PARAMS)
        it.setText("⚙" if has_params else "")
        it.setToolTip(params_tip or ("Custom params" if has_params else ""))

    # --- двойные клики: URL/Result ---
    def on_task_cell_double_clicked(self, row: int, col: int):
        table = self.ui.taskTable
        try:
            if col == COL_URL:
                url_item = table.item(row, COL_URL)
                if not url_item:
                    return
                tip = (url_item.toolTip() or url_item.text() or "").strip()
                full_url = tip.split("\n", 1)[0].strip()
                if full_url:
                    QDesktopServices.openUrl(QUrl.fromUserInput(full_url))
                return

            if col == COL_RESULT:
                res_item = table.item(row, COL_RESULT)
                path = ((res_item.toolTip() or res_item.text()) if res_item else "").strip()
                if path:
                    self._open_path(path)
                    return
                # фолбэк: открыть URL, если пути нет
                url_item = table.item(row, COL_URL)
                if url_item:
                    tip = (url_item.toolTip() or url_item.text() or "").strip()
                    full_url = tip.split("\n", 1)[0].strip()
                    if full_url:
                        QDesktopServices.openUrl(QUrl.fromUserInput(full_url))
                return

            if col == COL_PARAMS:
                self._ctx_edit_params_dialog(row)
                return

        except Exception as e:
            try:
                self.append_log_line(f"[ERROR] on_task_cell_double_clicked: {e}")
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
        params = params or {}
        task_id = self.task_manager.create_task(url, params)

        row = self.ui.taskTable.rowCount()
        self.ui.taskTable.insertRow(row)

        # URL-ячейка (храним task_id в UserRole)
        url_item = QTableWidgetItem("")
        url_item.setData(Qt.UserRole, task_id)
        self.ui.taskTable.setItem(row, COL_URL, url_item)

        # Базовые колонки
        self.set_url_cell(row, url)
        self.set_status_cell(row, TaskStatus.PENDING.value)
        self.set_code_cell(row, None)
        self.set_time_cell(row, None)
        self.set_result_cell(row, None)

        # Индикатор PARAMS (показываем только ключевые поля в tooltip)
        params_light = {k: params.get(k) for k in ("method", "proxy", "user_agent", "timeout", "retries") if params.get(k)}
        self.set_params_cell(row, bool(params_light), str(params_light) if params_light else "")

        # Индикатор COOKIES (на старте пусто, заполним в on_task_result по Set-Cookie)
        self.set_cookies_cell(row, False, "")

        # Индексы строк
        self._row_by_task_id[task_id] = row

        # Автоподгон
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
        # URL, код, заголовок
        url = payload.get("final_url") or payload.get("url", "") or ""
        code = payload.get("status_code", "")
        title = (payload.get("title") or "").strip()

        # размер контента
        size_bytes = payload.get("content_len")
        try:
            size_bytes = int(size_bytes) if size_bytes is not None else None
        except Exception:
            size_bytes = None

        # тайминги
        timings = payload.get("timings", {}) or {}
        t_req = timings.get("request_ms")
        try:
            t_req = int(t_req) if t_req is not None else None
        except Exception:
            t_req = None

        # редиректы
        redirects = payload.get("redirect_chain", []) or []
        redirect_count = len(redirects)

        # заголовки
        headers = payload.get("headers", {}) or {}
        hdr_pairs = []
        for k in ("server", "content-type", "content-length", "date", "via", "x-powered-by", "cf-ray"):
            if k in headers or k.title() in headers:
                v = headers.get(k, headers.get(k.title()))
                hdr_pairs.append(f"    {k}: {v}")
        hdr_block = ("\n" + "\n".join(hdr_pairs)) if hdr_pairs else ""

        size_line = f"{size_bytes} bytes" if size_bytes is not None else "(unknown)"
        time_line = f"{t_req} ms" if t_req is not None else "(unknown)"
        redirect_line = f"{redirect_count} redirect(s)" if redirect_count else "No redirects"

        lines = [
            f"  URL: {url}",
            f"  Status: {code}",
            f"  Title: {title}" if title else "  Title: (none)",
            f"  Size: {size_line}",
            f"  Time: request {time_line}",
            f"  Redirects: {redirect_line}",
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
        if row_under_cursor >= 0 and row_under_cursor not in self._selected_rows():
            table.clearSelection()
            table.selectRow(row_under_cursor)

        has_selection = len(self._selected_rows()) > 0
        single_row = has_selection and len(self._selected_rows()) == 1
        row = self._selected_rows()[0] if single_row else -1

        menu = QMenu(self)

        # ▶ Действия запуска
        act_start   = menu.addAction("Start selected")
        act_stop    = menu.addAction("Stop selected")
        act_pause   = menu.addAction("Pause selected")    # ← добавлено
        act_resume  = menu.addAction("Resume selected")   # ← добавлено
        act_restart = menu.addAction("Restart selected")
        act_reset   = menu.addAction("Reset selected")
        menu.addSeparator()

        # ▶ Переходы/копирование
        act_open_url   = menu.addAction("Open URL in browser")
        act_copy_url   = menu.addAction("Copy URL")
        act_open_res   = menu.addAction("Open Result Folder")
        act_copy_hdrs  = menu.addAction("Copy Response Headers")
        menu.addSeparator()

        # ▶ Просмотр детальной инфы
        act_view_hdrs  = menu.addAction("View Response Headers…")
        act_view_redir = menu.addAction("View Redirects…")
        act_view_cookies = menu.addAction("View Cookies…")
        menu.addSeparator()

        # ▶ Настройки задачи
        act_edit_params = menu.addAction("Edit Params…")
        act_delete   = menu.addAction("Delete selected")

        # доступность
        for a in (act_start, act_stop, act_pause, act_resume, act_restart, act_reset, act_delete,
                act_open_url, act_copy_url, act_open_res, act_copy_hdrs,
                act_view_hdrs, act_view_redir, act_view_cookies, act_edit_params):
            a.setEnabled(has_selection)

        action = menu.exec(global_pos)
        if action is None:
            return

        if action == act_start:
            self.start_selected_tasks()
        elif action == act_stop:
            self.stop_selected_tasks()
        elif action == act_pause:          # ← добавлено
            self.pause_selected_tasks()
        elif action == act_resume:         # ← добавлено
            self.resume_selected_tasks()
        elif action == act_restart:
            self.restart_selected_tasks()
        elif action == act_reset:
            self.reset_selected_tasks()
        elif action == act_delete:
            self.delete_selected_tasks()
        elif action == act_open_url and single_row:
            self._ctx_open_url(row)
        elif action == act_copy_url and single_row:
            self._ctx_copy_url(row)
        elif action == act_open_res and single_row:
            self._ctx_open_result_folder(row)
        elif action == act_copy_hdrs and single_row:
            self._ctx_copy_response_headers(row)
        elif action == act_view_hdrs and single_row:
            self._ctx_view_headers_dialog(row)
        elif action == act_view_redir and single_row:
            self._ctx_view_redirects_dialog(row)
        elif action == act_view_cookies and single_row:
            self._ctx_view_cookies_dialog(row)
        elif action == act_edit_params and single_row:
            self._ctx_edit_params_dialog(row)

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
    def on_pause_clicked(self):  # ← добавлено
        ids = self._selected_task_ids()
        if not ids:
            self.append_log_line("[WARN] No tasks selected")
            return
        for tid in ids:
            self.task_manager.pause_task(tid)
        self.append_log_line(f"[UI] Pause clicked → {len(ids)} task(s)")

    @Slot()
    def on_resume_clicked(self):  # ← добавлено
        ids = self._selected_task_ids()
        if not ids:
            self.append_log_line("[WARN] No tasks selected")
            return
        for tid in ids:
            self.task_manager.resume_task(tid)
        self.append_log_line(f"[UI] Resume clicked → {len(ids)} task(s)")

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
        # Красивый блок в логи (с учётом final_url/content_len/timings.request_ms + redirects)
        pretty = self._format_result_short(payload)
        self.append_log_line(f"[RESULT][{task_id[:8]}]\n{pretty}")

        row = self._find_row_by_task_id(task_id)
        if row < 0:
            return

        # Ставим статус
        self.set_status_cell(row, "Done")

        # URL: предпочитаем final_url (после редиректов), фолбэк — исходный из задачи
        url_val = payload.get("final_url") or payload.get("url") or ""
        if not url_val:
            task = self.task_manager.get_task(task_id)
            if task:
                url_val = getattr(task, "url", "") or url_val
        self.set_url_cell(row, url_val, payload.get("title"))

        # Код ответа
        self.set_code_cell(row, payload.get("status_code"))

        # Время запроса (берём timings.request_ms)
        timings = payload.get("timings", {}) or {}
        self.set_time_cell(row, timings.get("request_ms"))

        # Подсказка по редиректам в статусе
        redirects = payload.get("redirect_chain", []) or []
        st_item = self.ui.taskTable.item(row, COL_STATUS)
        if st_item:
            st_item.setToolTip(f"Done • redirects: {len(redirects)}")

        # Cookies: по заголовку 'Set-Cookie'
        headers = payload.get("headers", {}) or {}
        low_headers = {k.lower(): v for k, v in headers.items()}
        set_cookie_val = low_headers.get("set-cookie")
        has_cookies = bool(set_cookie_val)
        tip = f"Set-Cookie: {set_cookie_val}" if isinstance(set_cookie_val, str) else ""
        self.set_cookies_cell(row, has_cookies, tip)

        # Params: есть ли кастомные параметры у задачи
        task = self.task_manager.get_task(task_id)
        has_params = False
        params_tip = ""
        if task:
            p = getattr(task, "params", {}) or {}
            has_params = bool(p) and any(k in p for k in ("headers", "proxy", "user_agent", "timeout", "retries", "method"))
            if has_params:
                light = {k: p.get(k) for k in ("method", "proxy", "user_agent", "timeout", "retries") if k in p}
                params_tip = str(light)
        self.set_params_cell(row, has_params, params_tip)



    @Slot(str, str)
    def on_task_error(self, task_id: str, error_str: str):
        self.append_log_line(f"[ERROR][{task_id[:8]}] {error_str}")
        
        
    #--------------- CTX ОБРАБОТЧИКИ -------------------#
    
    def _ctx_open_url(self, row: int):
        it = self.ui.taskTable.item(row, COL_URL)
        if not it:
            return
        tip = (it.toolTip() or it.text() or "").strip()
        full_url = tip.split("\n", 1)[0].strip()
        if full_url:
            QDesktopServices.openUrl(QUrl.fromUserInput(full_url))

    def _ctx_copy_url(self, row: int):
        it = self.ui.taskTable.item(row, COL_URL)
        if not it:
            return
        tip = (it.toolTip() or it.text() or "").strip()
        full_url = tip.split("\n", 1)[0].strip()
        if full_url:
            QGuiApplication.clipboard().setText(full_url)
            self.append_log_line("[INFO] URL copied to clipboard")

    def _ctx_open_result_folder(self, row: int):
        it = self.ui.taskTable.item(row, COL_RESULT)
        path = ((it.toolTip() or it.text()) if it else "").strip()
        if not path:
            # фолбэк — попробуем открыть папку экспорта
            base = exporter.default_exports_dir()
            os.makedirs(base, exist_ok=True)
            path = base
        self._open_path(path)

    def _ctx_copy_response_headers(self, row: int):
        # вытащим task_id → task → headers из последнего payload
        task_id = self._task_id_by_row(row)
        task = self.task_manager.get_task(task_id) if task_id else None
        headers = {}
        if task and getattr(task, "result", None):
            headers = (task.result or {}).get("headers", {}) or {}
        if not headers:
            self.append_log_line("[WARN] No headers available")
            return
        text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        QGuiApplication.clipboard().setText(text)
        self.append_log_line("[INFO] Headers copied to clipboard")

    def _ctx_view_headers_dialog(self, row: int):
        task_id = self._task_id_by_row(row)
        task = self.task_manager.get_task(task_id) if task_id else None
        headers = {}
        if task and getattr(task, "result", None):
            headers = (task.result or {}).get("headers", {}) or {}
        if not headers:
            QMessageBox.information(self, "Headers", "No headers available")
            return
        text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        QMessageBox.information(self, "Response Headers", text[:6000])  # простая заглушка

    def _ctx_view_redirects_dialog(self, row: int):
        task_id = self._task_id_by_row(row)
        task = self.task_manager.get_task(task_id) if task_id else None
        redirs = []
        if task and getattr(task, "result", None):
            redirs = (task.result or {}).get("redirect_chain", []) or []
        if not redirs:
            QMessageBox.information(self, "Redirects", "No redirects")
            return
        text = "\n".join(f"{h.get('status_code')} → {h.get('url')}" for h in redirs)
        QMessageBox.information(self, "Redirect history", text[:6000])

    def _ctx_view_cookies_dialog(self, row: int):
        task_id = self._task_id_by_row(row)
        task = self.task_manager.get_task(task_id) if task_id else None
        headers = {}
        if task and getattr(task, "result", None):
            headers = (task.result or {}).get("headers", {}) or {}
        low = {k.lower(): v for k, v in (headers or {}).items()}
        sc = low.get("set-cookie")
        if not sc:
            QMessageBox.information(self, "Cookies", "No Set-Cookie in response")
            return
        text = sc if isinstance(sc, str) else str(sc)
        QMessageBox.information(self, "Cookies", text[:6000])

    def _ctx_edit_params_dialog(self, row: int):
        task_id = self._task_id_by_row(row)
        task = self.task_manager.get_task(task_id) if task_id else None
        current = dict(getattr(task, "params", {}) or {})

        dlg = ParamsDialog(self, initial=current)

        # Новый путь: если у диалога есть сигналы — пользуемся ими
        if hasattr(dlg, "applied"):
            dlg.applied.connect(lambda params, r=row, tid=task_id: 
                                self._on_params_applied_ctx(r, tid, params, run=False))
        if hasattr(dlg, "applied_and_run"):
            dlg.applied_and_run.connect(lambda params, r=row, tid=task_id: 
                                        self._on_params_applied_ctx(r, tid, params, run=True))

        result = dlg.exec()

        # Fallback-режим: если сигналов нет (или не сработали), но диалог закрыт по OK — читаем data
        if result == QDialog.Accepted:
            new_params = getattr(dlg, "data", None)
            if new_params is None and hasattr(dlg, "get_data"):
                new_params = dlg.get_data()
            if new_params:
                self._on_params_applied_ctx(row, task_id, new_params, run=False)

    def _on_params_applied_ctx(self, row: int, task_id: str, params: dict, run: bool):
        # сохранить параметры в задачу
        try:
            if hasattr(self.task_manager, "update_task_params"):
                self.task_manager.update_task_params(task_id, params)
            else:
                task = self.task_manager.get_task(task_id)
                if task is not None:
                    setattr(task, "params", params)
        except Exception as e:
            self.append_log_line(f"[ERROR] update_task_params({task_id[:8]}): {e}")
            return

        # обновить ячейку Params (иконка ⚙ + tooltip)
        light = {k: params.get(k) for k in ("method","proxy","user_agent","timeout","retries") if params.get(k)}
        try:
            self.set_params_cell(row, bool(light), str(light) if light else "")
        except Exception:
            pass

        self.append_log_line(f"[INFO] Params updated for {task_id[:8]}")

        # Apply & Run → безопасный перезапуск
        if run:
            # если есть нативный метод — используем его
            if getattr(self.task_manager, "restart_task", None):
                try:
                    self.task_manager.restart_task(task_id)
                    self.append_log_line(f"[INFO] Task restarted with new params ({task_id[:8]})")
                    return
                except Exception as e:
                    self.append_log_line(f"[WARN] restart_task failed: {e}")
            # fallback: стоп (если бежит) → старт
            try:
                self.task_manager.stop_task(task_id)
            except Exception:
                pass
            try:
                self.task_manager.start_task(task_id)
                self.append_log_line(f"[INFO] Task started with new params ({task_id[:8]})")
            except Exception as e:
                self.append_log_line(f"[ERROR] start_task({task_id[:8]}): {e}")