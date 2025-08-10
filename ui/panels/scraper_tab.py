# ui/panels/scraper_tab.py
from __future__ import annotations  # ← должен быть первым
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from dialogs.params_dialog import ParamsDialog
from functools import partial
import os, json, httpx, subprocess
from PySide6.QtCore import Qt, Slot, QSettings, QUrl, QRegularExpression, QPoint
from PySide6.QtGui import QTextCursor, QSyntaxHighlighter, QTextCharFormat, QColor, QFont , QDesktopServices, QGuiApplication
from PySide6.QtWidgets import QWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QDialog, QMenu, QFileDialog, QInputDialog, QWidgetAction, QMessageBox

from .scraper_panel_ui import Ui_scraper_panel
from core.scraper.task_manager import TaskManager
from core.scraper import exporter
from core.cookies import storage
from core.scraper.task_types import TaskStatus
from dialogs.add_task_dialog import AddTaskDialog
from utils.context_menu import build_task_table_menu


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
    def on_context_menu(self, pos: QPoint):
        table = self.ui.taskTable

        # Разрешаем открывать меню и на пустом месте: будут доступны пункты для "all"
        # (build_task_table_menu сам решит, что включить/выключить)
        rows = sorted({idx.row() for idx in table.selectedIndexes()})
        count = len(rows)

        # ---- Сбор контекста по задачам (для build_task_table_menu) ----
        has_running = False
        has_stopped = False
        all_done = True
        has_params_cell = True
        has_cookie_file = False
        any_startable = False
        any_stoppable = False

        for r in rows:
            task_id = self._task_id_by_row(r)
            task = self.task_manager.get_task(task_id) if task_id else None
            status = getattr(task, "status", "PENDING")
            s = self._status_name(status)

            has_running |= (s == "RUNNING")
            has_stopped |= (s in {"PENDING", "STOPPED", "FAILED"})
            all_done &= (s == "DONE")

            # можно стартовать всё, что не RUNNING
            any_startable |= (s != "RUNNING")
            # можно останавливать RUNNING/PENDING
            any_stoppable |= (s in {"RUNNING", "PENDING"})

            # params
            params = getattr(task, "params", {}) if task else {}
            has_params_cell &= (params is not None)

            # cookies
            ck_file = params.get("cookie_file")
            has_cookie_file |= bool(ck_file)

        selection_info = {
            "rows": rows,
            "count": count,
            "has_running": has_running,
            "has_stopped": has_stopped,
            "all_done": all_done,
            "has_params_cell": has_params_cell,
            "has_cookie_file": has_cookie_file,
        }

        # Сбор меню и набора действий
        menu, acts = build_task_table_menu(self, selection_info)

        # ---------- Подключение экшенов (без лишних лямбд) ----------
        # Tasks: selection
        acts["start_selected"].triggered.connect(partial(self._start_selected, rows))
        acts["stop_selected"].triggered.connect(partial(self._stop_selected, rows))
        acts["restart_selected"].triggered.connect(partial(self._restart_selected, rows))

        # Tasks: all
        acts["start_all"].triggered.connect(self.start_all_tasks)
        acts["stop_all"].triggered.connect(self.stop_all_tasks)
        acts["restart_all"].triggered.connect(self.restart_all_tasks)

        # CRUD / Params
        if count == 1:
            acts["edit_params"].triggered.connect(partial(self._ctx_edit_params_dialog, rows[0]))
            acts["open_browser"].triggered.connect(partial(self._open_in_browser, rows[0]))
            acts["copy_url"].triggered.connect(partial(self._copy_from_row, rows[0], "url"))
            acts["copy_final_url"].triggered.connect(partial(self._copy_from_row, rows[0], "final_url"))
            acts["copy_title"].triggered.connect(partial(self._copy_from_row, rows[0], "title"))
            acts["copy_headers"].triggered.connect(partial(self._copy_headers, rows[0]))
            acts["view_headers"].triggered.connect(partial(self._view_headers_dialog, rows[0]))
            acts["view_redirect_chain"].triggered.connect(partial(self._view_redirect_chain_dialog, rows[0]))
        acts["duplicate"].triggered.connect(partial(self._duplicate_tasks, rows))
        acts["remove"].triggered.connect(partial(self._remove_tasks, rows))

        # Export
        acts["export_selected"].triggered.connect(partial(self._export_data, "Selected"))
        acts["export_completed"].triggered.connect(partial(self._export_data, "Completed"))
        acts["export_all"].triggered.connect(partial(self._export_data, "All"))

        # Data ops
        acts["clear_results"].triggered.connect(partial(self._clear_results, rows))

        # Cookies
        acts["view_cookies"].triggered.connect(partial(self._view_cookies, rows[0]) if count >= 1 else lambda: None)
        acts["open_cookie_dir"].triggered.connect(self._open_cookie_dir)
        acts["reload_cookies"].triggered.connect(partial(self._reload_cookies, rows))
        acts["clear_cookies"].triggered.connect(partial(self._clear_cookies, rows))

        # Показ меню
        menu.exec(table.viewport().mapToGlobal(pos))


    # ==============================
    #  Служебные утилиты контекста
    # ==============================

    def _status_name(self, s) -> str:
        """Единообразное имя статуса (Enum/str → UPPER)."""
        name = getattr(s, "name", None)
        if name:
            return name.upper()
        s = str(s)
        if s.upper().startswith("TASKSTATUS."):
            s = s.split(".")[-1]
        return s.strip().upper() if s else "PENDING"


    # ==============================
    #  Слоты действий «Selected»
    #  (для кнопок и хоткеев)
    # ==============================

    @Slot()
    def _ctx_start_selected(self):
        self._start_selected(self._selected_rows())

    @Slot()
    def _ctx_stop_selected(self):
        self._stop_selected(self._selected_rows())

    @Slot()
    def _ctx_restart_selected(self):
        self._restart_selected(self._selected_rows())


    # ==============================
    #  Массовые операции над задачами
    # ==============================

    def _rows_to_task_ids(self, rows: list[int]) -> list[tuple[int, str]]:
        """Сопоставить строки с task_id, пропуская пустые и логируя проблемы."""
        out = []
        for r in rows:
            tid = self._task_id_by_row(r)
            if not tid:
                self.append_log_line(f"[WARN] No task_id for row {r}")
                continue
            out.append((r, tid))
        return out

    def _start_selected(self, rows: list[int]):
        pairs = self._rows_to_task_ids(rows)
        started = skipped = errors = 0
        for _, tid in pairs:
            try:
                self.task_manager.start_task(tid)
                started += 1
            except Exception as e:
                errors += 1
                self.append_log_line(f"[ERROR] start_selected({tid[:8]}): {e}")
        if skipped:
            self.append_log_line(f"[WARN] Start selected: skipped {skipped} task(s)")
        self.append_log_line(f"[INFO] Start selected: queued {started}, errors {errors}")

    def _stop_selected(self, rows: list[int]):
        pairs = self._rows_to_task_ids(rows)
        stopped = skipped = errors = 0
        for _, tid in pairs:
            try:
                task = self.task_manager.get_task(tid)
                s = self._status_name(getattr(task, "status", "PENDING"))
                if s in {"RUNNING", "PENDING"}:
                    self.task_manager.stop_task(tid)  # кооперативная остановка
                    stopped += 1
                else:
                    skipped += 1  # DONE/FAILED/STOPPED — останавливать нечего
            except Exception as e:
                errors += 1
                self.append_log_line(f"[ERROR] stop_selected({tid[:8]}): {e}")
        self.append_log_line(f"[INFO] Stop selected: requested {stopped}, skipped {skipped}, errors {errors}")

    def _restart_selected(self, rows: list[int]):
        pairs = self._rows_to_task_ids(rows)
        restarted = errors = 0
        has_restart = hasattr(self.task_manager, "restart_task")
        for _, tid in pairs:
            try:
                if has_restart:
                    self.task_manager.restart_task(tid)
                else:
                    # Фолбэк: мягко остановить и снова запустить
                    try:
                        self.task_manager.stop_task(tid)
                    finally:
                        self.task_manager.start_task(tid)
                restarted += 1
            except Exception as e:
                errors += 1
                self.append_log_line(f"[ERROR] restart_selected({tid[:8]}): {e}")
        self.append_log_line(f"[INFO] Restart selected: {restarted} task(s), errors {errors}")

    def _duplicate_tasks(self, rows: list[int]):
        """Дублирование выделенных задач (название во мн. числе для читаемости)."""
        pairs = self._rows_to_task_ids(rows)
        ok = errors = 0
        # поддержим и duplicate_task(task), и duplicate_tasks(task)
        dup_one = getattr(self.task_manager, "duplicate_task", None)
        dup_many = getattr(self.task_manager, "duplicate_tasks", None)

        for _, tid in pairs:
            task = self.task_manager.get_task(tid)
            if not task:
                continue
            try:
                if callable(dup_one):
                    dup_one(task)
                elif callable(dup_many):
                    dup_many(task)
                else:
                    raise RuntimeError("No duplicate_task(s) method in TaskManager")
                ok += 1
            except Exception as e:
                errors += 1
                self.append_log_line(f"[ERROR] duplicate({tid[:8]}): {e}")
        self.append_log_line(f"[INFO] Duplicated: {ok}, errors {errors}")

    def _remove_tasks(self, rows: list[int]):
        """Удаление задач из менеджера и таблицы. Гарантированно в обратном порядке строк."""
        pairs = self._rows_to_task_ids(rows)
        if not pairs:
            return
        # Снимем перерисовку, удалим строки «пакетом»
        table = self.ui.taskTable
        table.setUpdatesEnabled(False)
        removed = errors = 0
        try:
            # Сначала удалим из менеджера
            for _, tid in pairs:
                try:
                    self.task_manager.remove_task(tid)
                    removed += 1
                except Exception as e:
                    errors += 1
                    self.append_log_line(f"[ERROR] remove_task({tid[:8]}): {e}")

            # Затем удалим строки из таблицы (по убыванию индексов)
            for r, _ in sorted(pairs, key=lambda x: x[0], reverse=True):
                try:
                    table.removeRow(r)
                except Exception as e:
                    errors += 1
                    self.append_log_line(f"[ERROR] removeRow({r}): {e}")
        finally:
            table.setUpdatesEnabled(True)

        self.append_log_line(f"[INFO] Removed rows: {removed}, errors {errors}")


    # ==============================
    #  Экспорт данных
    # ==============================

    def _all_tasks_list(self):
        """Унифицированный способ получить список задач из TaskManager."""
        tm = self.task_manager
        if hasattr(tm, "all_tasks"):
            return list(tm.all_tasks())
        if hasattr(tm, "iter_tasks"):
            return list(tm.iter_tasks())
        if hasattr(tm, "_tasks"):
            return list(tm._tasks.values())
        if hasattr(tm, "tasks"):
            return list(tm.tasks.values())
        return []

    def _tasks_for_mode(self, mode: str):
        """Вернуть список задач для экспорта по режиму."""
        if mode == "Selected":
            ids = [self._task_id_by_row(r) for r in self._selected_rows()]
            return [self.task_manager.get_task(tid) for tid in ids if tid and self.task_manager.get_task(tid)]

        if mode == "Completed":
            out = []
            for t in self._all_tasks_list():
                s = self._status_name(getattr(t, "status", ""))
                if s == "DONE":
                    out.append(t)
            return out

        return self._all_tasks_list()

    def _task_to_record(self, t) -> dict:
        """Привести объект задачи к плоскому dict для экспорта (без потерь ключей из result)."""
        payload = getattr(t, "result", {}) or {}
        rec = dict(payload)  # все, что пришло из воркера
        rec.setdefault("task_id", getattr(t, "id", ""))
        rec.setdefault("url", getattr(t, "url", ""))
        rec.setdefault("title", payload.get("title") or getattr(t, "title", ""))
        rec["final_url"]   = payload.get("final_url") or rec.get("url", "")
        rec["status_code"] = payload.get("status_code")
        rec["content_len"] = payload.get("content_len")
        return rec

    def _ask_export_path(self, mode: str):
        """Показать Save As и вернуть (path:str, ext:str) или (None, None) при отмене."""
        import os, time
        from pathlib import Path
        from PySide6.QtWidgets import QFileDialog
        from PySide6.QtCore import QSettings

        ts = time.strftime("%Y%m%d_%H%M%S")
        default_name = f"export_{mode.lower()}_{ts}.csv"  # CSV по умолчанию
        settings = QSettings("WebSecSuite", "Scraper")
        last_dir = settings.value("export/last_dir", str(Path("data") / "exports"))
        Path(last_dir).mkdir(parents=True, exist_ok=True)

        path, selected_filter = QFileDialog.getSaveFileName(
            self, "Save results", str(Path(last_dir) / default_name),
            "CSV (*.csv);;JSON (*.json);;Excel (*.xlsx)"
        )
        if not path:
            return None, None

        # запоминаем папку
        settings.setValue("export/last_dir", str(Path(path).parent))

        ext = Path(path).suffix.lower()
        if ext not in {".csv", ".json", ".xlsx"}:
            if "JSON" in selected_filter:
                ext = ".json"; path = str(Path(path).with_suffix(".json"))
            elif "Excel" in selected_filter:
                ext = ".xlsx"; path = str(Path(path).with_suffix(".xlsx"))
            else:
                ext = ".csv"; path = str(Path(path).with_suffix(".csv"))
        return path, ext

    def _export_data(self, mode: str):
        """
        Диалог 'Save As' → выбор формата (CSV/JSON/XLSX) → экспорт.
        Сначала пробуем core.scraper.exporter, затем — встроенный фолбэк.
        """
        tasks = self._tasks_for_mode(mode)
        if not tasks:
            self.append_log_line(f"[WARN] Export: no tasks for mode '{mode}'")
            return

        path, ext = self._ask_export_path(mode)
        if not path:
            return

        # Попытка модульного экспортера
        used_builtin = False
        try:
            from core.scraper import exporter
            if ext == ".csv" and hasattr(exporter, "export_csv"):
                exporter.export_csv(tasks, path); used_builtin = True
            elif ext == ".json" and hasattr(exporter, "export_json"):
                exporter.export_json(tasks, path); used_builtin = True
            elif ext == ".xlsx" and hasattr(exporter, "export_xlsx"):
                exporter.export_xlsx(tasks, path); used_builtin = True
            elif hasattr(exporter, "export_tasks"):
                try:
                    exporter.export_tasks(tasks, path=path, fmt=ext.lstrip("."))
                    used_builtin = True
                except TypeError:
                    exporter.export_tasks(tasks, filename=path, format=ext.lstrip("."))
                    used_builtin = True
        except Exception as e:
            self.append_log_line(f"[WARN] Built‑in exporter error: {e}. Will fallback.")

        if used_builtin:
            self.append_log_line(f"[INFO] Exported ({mode}) → {path}")
            return

        # ---- Фолбэк: сбор записей ----
        records, keys = [], set()
        for t in tasks:
            rec = self._task_to_record(t)
            keys.update(rec.keys())
            records.append(rec)

        # Запись JSON
        if ext == ".json":
            import json, tempfile, os
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(records, f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)  # атомарная запись
            self.append_log_line(f"[INFO] Exported ({mode}) {len(records)} rows → {path}")
            return

        # Запись XLSX (если openpyxl доступен), иначе — в CSV
        if ext == ".xlsx":
            try:
                from openpyxl import Workbook
                wb = Workbook(); ws = wb.active
                headers = sorted(keys); ws.append(headers)
                for rec in records:
                    ws.append([("" if rec.get(k) is None else str(rec.get(k))) for k in headers])
                wb.save(path)
                self.append_log_line(f"[INFO] Exported ({mode}) {len(records)} rows → {path}")
                return
            except Exception as e:
                self.append_log_line(f"[WARN] XLSX export failed ({e}). Saving as CSV instead.")
                from pathlib import Path as _P
                path = str(_P(path).with_suffix(".csv"))
                ext = ".csv"

        # Запись CSV
        headers = sorted(keys)
        import csv as _csv, tempfile, os
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            w = _csv.DictWriter(f, fieldnames=headers)
            w.writeheader()
            for rec in records:
                w.writerow({k: ("" if rec.get(k) is None else str(rec.get(k))) for k in headers})
        os.replace(tmp, path)  # атомарная запись
        self.append_log_line(f"[INFO] Exported ({mode}) {len(records)} rows → {path}")

    # ==============================
    #  Данные / буфер обмена / диалоги
    # ==============================

    def _row_to_task(self, row: int):
        """Безопасно вернуть (task_id, task) по строке; иначе (None, None)."""
        tid = self._task_id_by_row(row)
        if not tid:
            return None, None
        task = self.task_manager.get_task(tid)
        if not task:
            return None, None
        return tid, task

    def _get_result_payload(self, row: int) -> dict:
        _, task = self._row_to_task(row)
        return (getattr(task, "result", {}) or {}) if task else {}

    def _json_pretty(self, data) -> str:
        try:
            return json.dumps(data, indent=4, ensure_ascii=False)
        except Exception:
            return str(data)

    def _clear_results(self, rows: list[int]):
        table = self.ui.taskTable
        table.setUpdatesEnabled(False)
        cleared = 0
        try:
            for r in rows:
                tid, task = self._row_to_task(r)
                if not task:
                    continue
                setattr(task, "result", None)
                cleared += 1
                # при желании можно сразу очистить UI‑колонки результата:
                # self.set_code_cell(r, None)
                # self.set_url_cell(r, "", "")
                # self.set_status_cell(r, "PENDING")
        finally:
            table.setUpdatesEnabled(True)
        self.append_log_line(f"[INFO] Cleared results for {cleared} task(s)")

    def _open_in_browser(self, row: int):
        url = self.get_url_from_row(row)
        if not url:
            self.append_log_line("[WARN] Open in browser: empty URL")
            return
        ok = QDesktopServices.openUrl(QUrl(url))
        if not ok:
            import webbrowser
            webbrowser.open(url)

    def get_url_from_row(self, row: int) -> str:
        payload = self._get_result_payload(row)
        return payload.get("final_url") or payload.get("url") or ""

    def _get_field_from_row(self, row: int, field: str):
        payload = self._get_result_payload(row)
        return payload.get(field) or ""

    def _copy_from_row(self, row: int, field: str):
        val = self._get_field_from_row(row, field)
        if not val:
            self.append_log_line(f"[WARN] Copy {field}: empty")
            return
        QGuiApplication.clipboard().setText(str(val))
        # лог не раздуваем: показываем обрезку до 120 символов
        shown = str(val)
        if len(shown) > 120:
            shown = shown[:117] + "..."
        self.append_log_line(f"[INFO] Copied {field}: {shown}")

    def _copy_headers(self, row: int):
        payload = self._get_result_payload(row)
        hdrs = (payload or {}).get("headers") or {}
        self._copy_text_block(hdrs)

    def _copy_text_block(self, data):
        QGuiApplication.clipboard().setText(self._json_pretty(data))
        # без избыточных логов — это вспомогательный метод

    def _view_headers_dialog(self, row: int):
        payload = self._get_result_payload(row)
        hdrs = (payload or {}).get("headers") or {}
        self._show_json_dialog("Response Headers", hdrs)

    def _view_redirect_chain_dialog(self, row: int):
        payload = self._get_result_payload(row)
        chain = (payload or {}).get("redirect_chain") or []
        title = f"Redirect chain ({len(chain)})"
        self._show_json_dialog(title, chain)

    def _show_json_dialog(self, title: str, data):
        text = self._json_pretty(data)
        dlg = QMessageBox(self)
        dlg.setWindowTitle(title)
        dlg.setIcon(QMessageBox.Information)
        dlg.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
        # Для больших объёмов лучше уводить текст в detailedText (скролл) — не обязательно.
        if len(text) > 4000:
            dlg.setText(f"{title} — content is large, see details.")
            dlg.setDetailedText(text)
        else:
            dlg.setText(text)
        dlg.exec()

    # ==============================
    #  Cookies
    # ==============================

    def _cookie_path_for(self, url: str, cookie_file: str | None) -> Path:
        """
        Вернуть абсолютный путь к cookie-файлу:
        - если передан cookie_file — используем его;
        - иначе строим auto-путь по домену: data/cookies/cookies_<domain>.json.
        """
        if cookie_file:
            p = Path(cookie_file)
            return p if p.is_absolute() else (Path("data") / "cookies" / p)
        host = (urlparse(url).hostname or "default").lstrip(".")
        return Path("data") / "cookies" / f"cookies_{host}.json"


    def _open_cookie_dir(self):
        path = Path("data") / "cookies"
        path.mkdir(parents=True, exist_ok=True)

        # Кроссплатформенно через Qt; на Windows откроет Проводник
        ok = QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.resolve())))
        if not ok:
            # резерв на всякий случай
            if os.name == "nt":
                subprocess.Popen(f'explorer "{path.resolve()}"')
            else:
                subprocess.Popen(["xdg-open", str(path.resolve())])


    def _reload_cookies(self, rows: list[int]):
        """Перезагрузка cookie из файлов для выбранных задач (в память задачи/сессии)."""
        reloaded = skipped = 0
        for r in rows:
            tid = self._task_id_by_row(r)
            if not tid:
                skipped += 1
                continue
            task = self.task_manager.get_task(tid)
            if not task:
                skipped += 1
                continue

            params = getattr(task, "params", {}) or {}
            url = getattr(task, "url", "") or ""
            cookie_file = params.get("cookie_file")

            # 1) загрузим jar (storage сам решает: по cookie_file или по домену)
            try:
                jar, path, loaded = storage.load_cookiejar(url=url, cookie_file=cookie_file)
            except Exception as e:
                self.append_log_line(f"[ERROR] Cookies reload({tid[:8]}): {e}")
                continue

            # 2) положим в задачу (унифицированно используем httpx.Cookies)
            try:
                cookies = httpx.Cookies()
                for c in storage.jar_iter(jar):  # если есть helper; иначе конвертируем напрямую
                    cookies.set(c.name, c.value, domain=c.domain, path=c.path, expires=c.expires)
                setattr(task, "cookies", cookies)
                reloaded += 1

                # Если cookie_file не указан и storage выбрал auto-путь — пропишем его в params
                if not cookie_file:
                    params["cookie_file"] = str(path)
                    setattr(task, "params", params)

                self.append_log_line(f"[INFO] Cookies reloaded({tid[:8]}): {loaded} from {path}")
            except Exception as e:
                self.append_log_line(f"[ERROR] Cookies attach({tid[:8]}): {e}")

        self.append_log_line(f"[INFO] Cookies reloaded for {reloaded} task(s), skipped {skipped}")


    def _clear_cookies(self, rows: list[int]):
        """Очистка cookie в памяти задач (файлы не трогаем)."""
        cleared = skipped = 0
        for r in rows:
            tid = self._task_id_by_row(r)
            if not tid:
                skipped += 1
                continue
            task = self.task_manager.get_task(tid)
            if not task:
                skipped += 1
                continue
            try:
                setattr(task, "cookies", httpx.Cookies())  # чистая банка
                cleared += 1
            except Exception as e:
                self.append_log_line(f"[ERROR] Cookies clear({tid[:8]}): {e}")
        self.append_log_line(f"[INFO] Cookies cleared for {cleared} task(s), skipped {skipped}")


    def _view_cookies(self, row: int):
        """Показать cookies задачи (из файла, не из памяти) в удобном JSON."""
        task_id = self._task_id_by_row(row)
        if not task_id:
            return
        task = self.task_manager.get_task(task_id)
        if not task:
            return

        params = getattr(task, "params", {}) or {}
        url = getattr(task, "url", "") or ""
        cookie_file = params.get("cookie_file")

        try:
            jar, path, loaded = storage.load_cookiejar(url=url, cookie_file=cookie_file)
        except Exception as e:
            self.append_log_line(f"[ERROR] Cookies view({task_id[:8]}): {e}")
            QMessageBox.warning(self, "Cookies", f"Failed to load cookies:\n{e}")
            return

        if loaded == 0:
            QMessageBox.information(self, "Cookies", f"No cookies found.\nPath: {path}")
            return

        try:
            data = storage.jar_to_json(jar)
            pretty = json.dumps(data, indent=4, ensure_ascii=False)
        except Exception:
            pretty = "Could not serialize cookies."

        title = f"Cookies — {loaded} item(s)"
        text = f"Path: {path}\nLoaded: {loaded}\n\n{pretty}"

        # Для больших наборов отдаём в detailedText, чтобы не подвешивать QMessageBox
        dlg = QMessageBox(self)
        dlg.setWindowTitle(title)
        dlg.setIcon(QMessageBox.Information)
        dlg.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
        if len(text) > 4000:
            dlg.setText(f"{title}\nPath: {path}\nLoaded: {loaded}\n\n(See details)")
            dlg.setDetailedText(pretty)
        else:
            dlg.setText(text)
        dlg.exec()

        
    # --- ALL TASKS ACTIONS ---

    def start_all_tasks(self):
        """Запускает все задачи, которые не RUNNING. Разрешаем повторный старт DONE/FAILED."""
        table = self.ui.taskTable
        started = 0
        for row in range(table.rowCount()):
            tid = self._task_id_by_row(row)
            if not tid:
                continue
            task = self.task_manager.get_task(tid)
            status = getattr(task, "status", "PENDING")
            # Стартуем всё, что не RUNNING (включая DONE/FAILED для повторного прогона)
            if status in ("PENDING", "STOPPED", "FAILED", "DONE"):
                try:
                    self.task_manager.start_task(tid)
                    started += 1
                except Exception as e:
                    self.append_log_line(f"[ERROR] start_all_tasks({tid[:8]}): {e}")
        self.append_log_line(f"[INFO] Start all: queued {started} task(s)")


    def stop_all_tasks(self):
        """Кооперативно останавливает все RUNNING/PENDING задачи."""
        table = self.ui.taskTable
        stopped = 0
        for row in range(table.rowCount()):
            tid = self._task_id_by_row(row)
            if not tid:
                continue
            task = self.task_manager.get_task(tid)
            status = getattr(task, "status", "PENDING")
            if status in ("RUNNING", "PENDING"):
                try:
                    self.task_manager.stop_task(tid)
                    stopped += 1
                except Exception as e:
                    self.append_log_line(f"[ERROR] stop_all_tasks({tid[:8]}): {e}")
        self.append_log_line(f"[INFO] Stop all: requested stop for {stopped} task(s)")


    def restart_all_tasks(self):
        """
        Перезапуск всех задач:
        - если есть TaskManager.restart_task → используем его
        - иначе: stop_task → start_task (мягко; менеджер сам дождётся остановки воркера)
        """
        table = self.ui.taskTable
        restarted = 0
        use_native = hasattr(self.task_manager, "restart_task")

        for row in range(table.rowCount()):
            tid = self._task_id_by_row(row)
            if not tid:
                continue
            try:
                if use_native:
                    self.task_manager.restart_task(tid)
                else:
                    # Универсальный путь: остановить если бежит, затем стартовать
                    task = self.task_manager.get_task(tid)
                    status = getattr(task, "status", "PENDING")
                    if status in ("RUNNING", "PENDING"):
                        self.task_manager.stop_task(tid)
                    self.task_manager.start_task(tid)
                restarted += 1
            except Exception as e:
                self.append_log_line(f"[ERROR] restart_all_tasks({tid[:8]}): {e}")

        self.append_log_line(f"[INFO] Restart all: requested restart for {restarted} task(s)")
                    
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
        url = getattr(task, "url", "")

        dlg = ParamsDialog(self, initial=current, task_url=url)

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