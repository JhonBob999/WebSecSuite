# ui/panels/scraper_tab.py
from __future__ import annotations  # ← должен быть первым
from pathlib import Path
from urllib.parse import urlparse
from dialogs.params_dialog import ParamsDialog
from functools import partial
from copy import deepcopy
import os, json, httpx, subprocess, re
from PySide6.QtCore import Qt, Slot, QSettings, QUrl, QPoint, QTimer, QDateTime
from PySide6.QtGui import QTextCursor, QTextCharFormat, QColor, QFont , QDesktopServices, QGuiApplication, QBrush
from PySide6.QtWidgets import QWidget, QTableWidgetItem, QAbstractItemView, QHeaderView, QDialog, QFileDialog, QInputDialog, QMessageBox, QTextEdit
from ui.constants import Col, TaskStatus, status_text, status_brush, code_color, code_text, build_col_index_from_headers
from ui.log_highlighter import LogHighlighter
from ui.log_panel import LogPanel
from .scraper_panel_ui import Ui_scraper_panel
from core.scraper.task_manager import TaskManager
from core.scraper import exporter
from core.cookies import storage
from core.scraper.task_types import TaskStatus
from dialogs.add_task_dialog import AddTaskDialog
from utils.context_menu import build_task_table_menu

# --- палитра ---
CLR_STATUS = {
    "Running": QColor("#4aa3ff"),  # синий
    "Done":    QColor("#2ecc71"),  # зелёный
    "Failed":  QColor("#e74c3c"),  # красный
    "Stopped": QColor("#95a5a6"),  # серый
    "Pending": QColor("#bdc3c7"),  # светло-серый
    "Paused":  QColor("#f1c40f"),  # жёлтый
}

# --- статусные константы и отображаемые ярлыки ---
STATUS = {
    "RUNNING": "Running",
    "DONE":    "Done",
    "FAILED":  "Failed",
    "STOPPED": "Stopped",
    "PENDING": "Pending",
    "PAUSED":  "Paused",
}

# частые группы состояний
CAN_START = {"PENDING", "STOPPED", "FAILED", "DONE"}   # что можно запускать
CAN_STOP  = {"RUNNING", "PENDING"}                     # что можно останавливать


def status_label(name_upper: str) -> str:
    """UPPER → человекочитаемый ярлык (Title-case)"""
    return STATUS.get(name_upper, name_upper.title())

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



class ScraperTabController(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        # 1) Поднимаем UI
        self.ui = Ui_scraper_panel()
        self.ui.setupUi(self)
        
        # Хранилище результатов задач для предпросмотра
        self.task_results = {}  # ключ: row, значение: deepcopy(payload)
        
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
        
        # в __init__ сразу после установки заголовков:
        headers = [
            self.ui.taskTable.horizontalHeaderItem(i).text()
            for i in range(self.ui.taskTable.columnCount())
        ]
        self._col_map = build_col_index_from_headers(headers)
        
        # --- FIND STATE (для логов) ---
        self._find_positions = []  # list[(start, length)]
        self._find_current = -1    # индекс текущего совпадения
        self._find_debounce = QTimer(self)  # чтобы не дёргать поиск на каждый символ
        self._find_debounce.setSingleShot(True)
        self._find_debounce.setInterval(150)
        
        # ▼▼▼ ЛОГ-БУФЕР И ФИЛЬТР (п.2 из next_step)
        self.log_buffer = []                  # list[tuple[str, str, str]]: (ts, level, text)
        self.log_filter = {"INFO", "WARN", "ERROR"}
        self.MAX_LOG_LINES = 5000
        
        self.log = LogPanel(
        self.ui.logOutput,
        line_edit=self.ui.lineEditLogFilter,
        cb_case=self.ui.cbFindCase,
        cb_regex=self.ui.cbFindRegex,
        cb_whole=self.ui.cbFindWhole,
        counter_label=self.ui.lblFindHits,        # используем lblFindHits, раз он у тебя главный
        export_btn=self.ui.btnExportMatches,      # кнопка экспорта
        root_dir="data/logs",
        )
        self.ui.btnFindPrev.clicked.connect(self.log.navigate_prev)
        self.ui.btnFindNext.clicked.connect(self.log.navigate_next)

        # контекстное меню
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(self.on_context_menu)

        # 👉 Автоподгон размеров
        hh: QHeaderView = table.horizontalHeader()
        vh: QHeaderView = table.verticalHeader()
        hh.setSectionResizeMode(Col.URL, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(Col.Status, QHeaderView.ResizeToContents)
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
        # подключение кнопки (в __init__)
        self.ui.btnDataPreview.clicked.connect(self._open_data_preview_all)


        self._init_ui_connections()


    def _snapshot_records(self, only_selected: bool) -> list[dict]:
        from copy import deepcopy
        rows = self._selected_rows() if only_selected else range(self.ui.taskTable.rowCount())
        records: list[dict] = []
        for row in rows:
            task = self._row_to_task(row)
            if not task:
                continue
            payload = getattr(task, "result", None) or {}
            if not payload:
                continue
            rec = deepcopy(payload)
            t = (payload.get("timings") or {})
            rec["request_ms"] = t.get("request_ms")
            rc = payload.get("redirect_chain") or []
            rec["redirects"] = len(rc)
            rec.setdefault("final_url", payload.get("final_url") or payload.get("url"))
            rec.setdefault("status_code", payload.get("status_code"))
            rec.setdefault("title", payload.get("title"))
            rec.setdefault("content_len", payload.get("content_len"))
            records.append(rec)
        return records

    def _open_data_preview_all(self):
        from dialogs.data_preview_dialog import DataPreviewDialog
        table = self.ui.taskTable
        rows_all = range(table.rowCount())

        dlg = DataPreviewDialog(
            self,
            fetch_all=lambda: self._records_from_rows(range(self.ui.taskTable.rowCount())),
            fetch_selected=lambda: self._records_from_rows(self._selected_rows()),
        )
        dlg.set_records(self._records_from_rows(rows_all))
        dlg.show()

        
    def _col_index(self, name: str) -> int:
        """Временный адаптер, чтобы старый код не падал, пока переписываем на Col.*"""
        # если в карте нет — вернём значение из enum (по умолчанию)
        try:
            return self._col_map.get(name, getattr(Col, name))
        except Exception:
            # на всякий случай, чтобы не уронить UI при опечатке
            return getattr(Col, name, 0)

    # ---------- ИНИЦИАЛИЗАЦИЯ КНОПОК ФИЛЬТРОВ ----------
    def _init_ui_connections(self):
        # Clear — очищает экран, но НЕ буфер
        if hasattr(self.ui, "btnClearLog"):
            self.ui.btnClearLog.clicked.connect(self._clear_log_screen)
                     
    def _on_filter_text_changed(self, text: str):
        # проксируем к новой системе поиска
        if hasattr(self, "log"):
            self.log._on_filter_changed(text)

    def _apply_log_find_selections(self, positions, current_index=-1):
        edit = self.ui.logOutput
        doc = edit.document()

        # Блеклая подсветка для всех совпадений
        fmt_all = QTextCharFormat()
        fmt_all.setBackground(Qt.yellow)
        fmt_all.setProperty(QTextCharFormat.FullWidthSelection, False)

        # Яркая рамка/подсветка для текущего
        fmt_cur = QTextCharFormat()
        fmt_cur.setBackground(Qt.darkYellow)
        fmt_cur.setUnderlineStyle(QTextCharFormat.SingleUnderline)

        sels = []
        for i, (start, length) in enumerate(positions):
            cur = QTextCursor(doc)
            cur.setPosition(start)
            cur.setPosition(start + length, QTextCursor.KeepAnchor)

            s = QTextEdit.ExtraSelection()
            s.cursor = cur
            s.format = fmt_cur if i == current_index else fmt_all
            sels.append(s)

        # Сочетается с твоим syntax highlighter — ExtraSelections поверх
        edit.setExtraSelections(sels)
        
    def _ensure_current_visible(self):
        if self._find_current < 0 or self._find_current >= len(self._find_positions):
            return
        start, length = self._find_positions[self._find_current]
        doc = self.ui.logOutput.document()
        cur = QTextCursor(doc)
        cur.setPosition(start)
        cur.setPosition(start + length, QTextCursor.KeepAnchor)
        self.ui.logOutput.setTextCursor(cur)
        self.ui.logOutput.ensureCursorVisible()
        
    def _update_find_label(self):
        total = len(self._find_positions)
        cur = (self._find_current + 1) if total and self._find_current >= 0 else 0
        self.ui.lblFindHits.setText(f"{cur} / {total}")
        # Активность кнопок
        enabled = total > 0
        self.ui.btnFindPrev.setEnabled(enabled)
        self.ui.btnFindNext.setEnabled(enabled)
        
    def _set_find_error(self, is_error: bool):
        le = self.ui.lineEditLogFilter
        if is_error:
            le.setStyleSheet("QLineEdit { border: 1px solid #dc3545; }")
            self.ui.lblFindHits.setText("ERR")
            self.ui.btnFindPrev.setEnabled(False)
            self.ui.btnFindNext.setEnabled(False)
        else:
            le.setStyleSheet("")
            
    def _current_find_regex(self):
        """Строим regex из текущего текста и флагов (те же правила, что в _rebuild_find_matches)."""
        text = self.ui.lineEditLogFilter.text()
        if not text:
            return None

        use_regex = self.ui.cbFindRegex.isChecked()
        case_sensitive = self.ui.cbFindCase.isChecked()
        whole_word = self.ui.cbFindWhole.isChecked()
        flags = 0 if case_sensitive else re.IGNORECASE

        try:
            if use_regex:
                pattern = text
                if whole_word:
                    # добавляем \b только если пользователь сам не поставил
                    if not pattern.startswith(r"\b"):
                        pattern = r"\b" + pattern
                    if not pattern.endswith(r"\b"):
                        pattern = pattern + r"\b"
                rx = re.compile(pattern, flags)
            else:
                pattern = re.escape(text)
                if whole_word:
                    pattern = rf"\b{pattern}\b"
                rx = re.compile(pattern, flags)
            return rx
        except re.error:
            return None
        
    
        
    def _ask_export_path_log(self):
        ts = QDateTime.currentDateTime().toString("yyyyMMdd_hhmmss")
        suggested = os.path.join("data", "exports", f"log_search_{ts}.txt")
        os.makedirs(os.path.dirname(suggested), exist_ok=True)
        path, _ = QFileDialog.getSaveFileName(
            self.ui.taskTable, "Export matches", suggested, "Text (*.txt);;JSON (*.json)"
        )
        return path or ""
          
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
        it = self._ensure_item(row, Col.URL)
        it.setText(self._shorten_url(url))
        tip = url if not page_title else f"{url}\nTitle: {page_title}"
        it.setToolTip(tip)

    def set_status_cell(self, row: int, status: str) -> None:
        table = self.ui.taskTable
        col = Col.Status   # ← финальная форма
        item = table.item(row, col)
        if item is None:
            item = self._ensure_item(row, col)

        text = status_text(status)
        item.setText(text)

        brush = status_brush(status)
        item.setBackground(brush if brush else QBrush())

        bold = str(status).upper() in (TaskStatus.RUNNING, TaskStatus.FAILED)
        f = item.font()
        f.setBold(bold)
        item.setFont(f)
        item.setToolTip(text)


    def set_code_cell(self, row: int, code: int | str | None):
        it = self._ensure_item(row, Col.Code)
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
        it = self._ensure_item(row, Col.Time)
        if elapsed_ms is None:
            it.setText(""); it.setToolTip(""); return
        ms = float(elapsed_ms)
        text = f"{int(ms)} ms" if ms < 1000 else f"{ms/1000:.2f} s"
        it.setText(text)
        it.setToolTip(f"Elapsed: {int(ms)} ms")
        
    def set_cookies_cell(self, row: int, has_cookies: bool, cookies_tip: str = ""):
        it = self._ensure_item(row, Col.Cookies)
        it.setText("✔" if has_cookies else "")
        it.setToolTip(cookies_tip or ("Set-Cookie present" if has_cookies else ""))

    def set_params_cell(self, row: int, has_params: bool, params_tip: str = ""):
        it = self._ensure_item(row, Col.Params)
        it.setText("⚙" if has_params else "")
        it.setToolTip(params_tip or ("Custom params" if has_params else ""))

    # --- двойные клики: URL/Result ---
    def on_task_cell_double_clicked(self, row: int, col: int):
        table = self.ui.taskTable
        try:
            if col == Col.URL:
                url_item = table.item(row, Col.URL)
                if not url_item:
                    return
                tip = (url_item.toolTip() or url_item.text() or "").strip()
                full_url = tip.split("\n", 1)[0].strip()
                if full_url:
                    QDesktopServices.openUrl(QUrl.fromUserInput(full_url))
                return

            if col == Col.Results:
                res_item = table.item(row, Col.Results)
                # Если Results уже заполнен — показываем JSON (tooltip), НО НИЧЕГО не открываем
                if res_item and (res_item.text() or res_item.toolTip()):
                    tip = (res_item.toolTip() or "").strip()
                    if tip:
                        self._show_json_dialog(Col.Results, tip)
                    return
                # Иначе (пусто) — фолбэк: открыть URL
                url_item = table.item(row, Col.URL)
                if url_item:
                    tip = (url_item.toolTip() or url_item.text() or "").strip()
                    full_url = tip.split("\n", 1)[0].strip()
                    if full_url:
                        QDesktopServices.openUrl(QUrl.fromUserInput(full_url))
                return

            if col == Col.Params:
                self._ctx_edit_params_dialog(row)
                return

        except Exception as e:
            try:
                self.log.append_log_line(f"[ERROR] on_task_cell_double_clicked: {e}")
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
        ts = QDateTime.currentDateTime().toString("HH:mm:ss")

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


    # --- Clipboard utilities -------------------------------------------------
    def _copy_to_clipboard(self, text: str, label: str = "") -> None:
        """
        Копирует text в буфер обмена и пишет единый лог.
        """
        try:
            QGuiApplication.clipboard().setText(text or "")
            self.log._log("INFO", f"Copied to clipboard {f'({label})' if label else ''}".strip(), "UI")
        except Exception as e:
            self.log._log("ERROR", f"Clipboard error: {e}", "UI")


    # ---------- Таблица и строки ----------
    def add_task_row(self, url: str, params: dict | None = None) -> None:
        params = params or {}
        task_id = self.task_manager.create_task(url, params)

        row = self.ui.taskTable.rowCount()
        self.ui.taskTable.insertRow(row)

        # URL-ячейка (храним task_id в UserRole)
        url_item = QTableWidgetItem("")
        url_item.setData(Qt.UserRole, task_id)
        self.ui.taskTable.setItem(row, Col.URL, url_item)

        # Базовые колонки
        self.set_url_cell(row, url)
        self.set_status_cell(row, TaskStatus.PENDING)
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
        
        
    def set_result_cell(self, row, payload):
        """Совместимость со старым кодом — перенаправляем в set_results_cell."""
        self.set_results_cell(row, payload)
        it = self.ui.taskTable.item(row, Col.Results)
        self.log.append_log_line(f"[DEBUG] Results set? {bool(it)} text={it.text() if it else None}")


    # ---------- Хелперы для выделения/ID и батч-операций ----------
    def _selected_rows(self):
        sel = self.ui.taskTable.selectionModel()
        if not sel or not sel.hasSelection():
            return []
        return sorted({idx.row() for idx in sel.selectedRows()})

    def _task_id_by_row(self, row: int) -> str | None:
        it = self.ui.taskTable.item(row, Col.URL)
        return it.data(Qt.UserRole) if it else None

    def start_selected_tasks(self):
        rows = self._selected_rows()
        if not rows:
            self.log.append_log_line("[WARN] No tasks selected")
            return
        for row in rows:
            task_id, _ = self._get_task(row)
            if not task_id:
                continue
            try:
                self.task_manager.start_task(task_id)
                self.log.append_log_line(f"[UI] Start task {task_id[:8]}")
            except Exception as e:
                self.log.append_log_line(f"[ERROR] start_task({task_id[:8]}): {e}")

    def stop_selected_tasks(self):
        rows = self._selected_rows()
        if not rows:
            self.log.append_log_line("[WARN] No tasks selected")
            return
        for row in rows:
            task_id, _ = self._get_task(row)
            if task_id:
                self.task_manager.stop_task(task_id)
        self.log.append_log_line(f"[UI] Stopped {len(rows)} task(s)")

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

        # Берём статус только из TaskStatus (если невалидный — ставим PENDING)
        status = getattr(task, "status", None)
        if status not in {
            TaskStatus.PENDING,
            TaskStatus.RUNNING,
            TaskStatus.DONE,
            TaskStatus.FAILED,
            TaskStatus.STOPPED,
        }:
            status = TaskStatus.PENDING

        self.set_status_cell(row, status)

    def _find_row_by_task_id(self, task_id: str) -> int:
        return self._row_by_task_id.get(task_id, -1)


    def reset_selected_tasks(self):
        ids = self._selected_task_ids()
        if not ids:
            self.log.append_log_line("[WARN] No rows selected for reset.")
            return
        ok = 0
        for tid in ids:
            if self.task_manager.reset_task(tid):
                ok += 1
                self._refresh_row_by_task_id(tid)
                self.log.append_log_line(f"[INFO] Task {tid} reset")
        self.log.append_log_line(f"[INFO] Reset done: {ok}/{len(ids)}")

    def restart_selected_tasks(self):
        ids = self._selected_task_ids()
        if not ids:
            self.log.append_log_line("[WARN] No rows selected for restart.")
            return
        ok = 0
        for tid in ids:
            if self.task_manager.restart_task(tid):
                ok += 1
                self.log.append_log_line(f"[INFO] Task {tid} restarted")
        self.log.append_log_line(f"[INFO] Restart done: {ok}/{len(ids)}")
        
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
            any_startable |= (s in CAN_START)
            # можно останавливать RUNNING/PENDING
            any_stoppable |= (s in CAN_STOP)

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
        """Единообразное имя статуса (TaskStatus | str → UPPER)."""
        if not s:
            return TaskStatus.PENDING.name

        # Enum TaskStatus
        if hasattr(s, "name"):
            return s.name.upper()

        # Строка вида "TaskStatus.DONE" или просто "done"
        s = str(s).strip()
        if not s:
            return TaskStatus.PENDING.name
        if s.upper().startswith("TASKSTATUS."):
            s = s.split(".", 1)[-1]
        return s.upper()


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
                self.log.append_log_line(f"[WARN] No task_id for row {r}")
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
                self.log.append_log_line(f"[ERROR] start_selected({tid[:8]}): {e}")
        if skipped:
            self.log.append_log_line(f"[WARN] Start selected: skipped {skipped} task(s)")
        self.log.append_log_line(f"[INFO] Start selected: queued {started}, errors {errors}")

    def _stop_selected(self, rows: list[int]):
        pairs = self._rows_to_task_ids(rows)
        stopped = skipped = errors = 0
        for _, tid in pairs:
            try:
                task = self.task_manager.get_task(tid)
                status = getattr(task, "status", TaskStatus.PENDING)
                s = self._status_name(status)
                if s in CAN_STOP:
                    self.task_manager.stop_task(tid)  # кооперативная остановка
                    stopped += 1
                else:
                    skipped += 1  # DONE/FAILED/STOPPED — останавливать нечего
            except Exception as e:
                errors += 1
                self.log.append_log_line(f"[ERROR] stop_selected({tid[:8]}): {e}")
        self.log.append_log_line(
            f"[INFO] Stop selected: requested {stopped}, skipped {skipped}, errors {errors}"
        )


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
                self.log.append_log_line(f"[ERROR] restart_selected({tid[:8]}): {e}")
        self.log.append_log_line(f"[INFO] Restart selected: {restarted} task(s), errors {errors}")

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
                self.log.append_log_line(f"[ERROR] duplicate({tid[:8]}): {e}")
        self.log.append_log_line(f"[INFO] Duplicated: {ok}, errors {errors}")

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
                    self.log.append_log_line(f"[ERROR] remove_task({tid[:8]}): {e}")

            # Затем удалим строки из таблицы (по убыванию индексов)
            for r, _ in sorted(pairs, key=lambda x: x[0], reverse=True):
                try:
                    table.removeRow(r)
                except Exception as e:
                    errors += 1
                    self.log.append_log_line(f"[ERROR] removeRow({r}): {e}")
        finally:
            table.setUpdatesEnabled(True)

        self.log.append_log_line(f"[INFO] Removed rows: {removed}, errors {errors}")


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
                status = getattr(t, "status", "")
                if status == TaskStatus.DONE:
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
            self.log.append_log_line(f"[WARN] Export: no tasks for mode '{mode}'")
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
            self.log.append_log_line(f"[WARN] Built‑in exporter error: {e}. Will fallback.")

        if used_builtin:
            self.log.append_log_line(f"[INFO] Exported ({mode}) → {path}")
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
            self.log.append_log_line(f"[INFO] Exported ({mode}) {len(records)} rows → {path}")
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
                self.log.append_log_line(f"[INFO] Exported ({mode}) {len(records)} rows → {path}")
                return
            except Exception as e:
                self.log.append_log_line(f"[WARN] XLSX export failed ({e}). Saving as CSV instead.")
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
        self.log.append_log_line(f"[INFO] Exported ({mode}) {len(records)} rows → {path}")

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
    
    # --- Task lookup ---------------------------------------------------------
    def _get_task(self, row: int):
        """
        Возвращает (task_id, task) для строки row.
        Читает task_id из UserRole URL-ячейки. Task — через публичный API TaskManager.
        """
        it = self.ui.taskTable.item(row, Col.URL)
        if not it:
            return None, None
        task_id = it.data(Qt.UserRole)
        if not task_id:
            return None, None
        task = self.task_manager.get_task(task_id)
        return task_id, task

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
        self.log.append_log_line(f"[INFO] Cleared results for {cleared} task(s)")

    def _open_in_browser(self, row: int):
        url = self.get_url_from_row(row)
        if not url:
            self.log.append_log_line("[WARN] Open in browser: empty URL")
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
        """
        Копирует значение из строки таблицы по имени поля в буфер обмена.
        Логирует результат с обрезкой длинного текста.
        """
        val = self._get_field_from_row(row, field)
        if not val:
            self.log._log("WARN", f"Copy {field}: empty", "UI")
            return

        text = str(val)
        # лог не раздуваем: показываем обрезку до 120 символов
        shown = text if len(text) <= 120 else text[:117] + "..."
        self._copy_to_clipboard(text, f"{field}: {shown}")


    def _copy_headers(self, row: int):
        payload = self._get_result_payload(row)
        headers = (payload or {}).get("headers") or {}
        if not headers:
            self.log._log("WARN", "No headers to copy", "UI")
            return

        pretty_headers = self._pretty_json(headers)
        self._copy_to_clipboard(pretty_headers, "Headers")

    def _copy_text_block(self, data):
        """
        Копирует JSON-сериализованный блок в буфер обмена.
        """
        pretty = self._pretty_json(data)
        self._copy_to_clipboard(pretty, "JSON block")


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
        # 1) Нормализация -> pretty string
        pretty = ""
        try:
            if isinstance(data, (dict, list)):
                pretty = json.dumps(data, ensure_ascii=False, indent=2)
            elif isinstance(data, (bytes, bytearray)):
                s = data.decode("utf-8", errors="replace")
                try:
                    pretty = json.dumps(json.loads(s), ensure_ascii=False, indent=2)
                except Exception:
                    pretty = s
            elif isinstance(data, str):
                s = data.strip()
                try:
                    # если это JSON-строка — красиво форматуем
                    pretty = json.dumps(json.loads(s), ensure_ascii=False, indent=2)
                except Exception:
                    pretty = s
            else:
                pretty = str(data)
        except Exception as e:
            pretty = f"<failed to format: {e}>"

        # 2) Диалог
        dlg = QMessageBox(self)
        dlg.setWindowTitle(title)
        dlg.setIcon(QMessageBox.Information)

        # Моноширинный шрифт
        mono = QFont("Consolas, Courier New, Monospace")
        mono.setStyleHint(QFont.Monospace)
        dlg.setFont(mono)

        # 3) Если текст очень длинный — уводим в Details (скролл)
        if len(pretty) > 4000:
            dlg.setText(f"{title}: content is large — see details below.")
            dlg.setDetailedText(pretty)
        else:
            dlg.setText(pretty)

        # Разрешаем копирование текста
        dlg.setTextInteractionFlags(
            Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard
        )

        dlg.exec()
        
    # --- JSON pretty-print ---------------------------------------------------
    def _pretty_json(self, data) -> str:
        """
        Преобразует dict/list/str в аккуратный JSON с utf-8.
        Если data — строка, пытается распарсить; при ошибке возвращает исходную.
        """
        try:
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    return data  # уже не JSON или не парсится — отдаём как есть
            return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False)
        except Exception as e:
            self.log._log("WARN", f"pretty_json failed: {e}")
            return str(data)



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
                self.log.append_log_line(f"[ERROR] Cookies reload({tid[:8]}): {e}")
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

                self.log.append_log_line(f"[INFO] Cookies reloaded({tid[:8]}): {loaded} from {path}")
            except Exception as e:
                self.log.append_log_line(f"[ERROR] Cookies attach({tid[:8]}): {e}")

        self.log.append_log_line(f"[INFO] Cookies reloaded for {reloaded} task(s), skipped {skipped}")


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
                self.log.append_log_line(f"[ERROR] Cookies clear({tid[:8]}): {e}")
        self.log.append_log_line(f"[INFO] Cookies cleared for {cleared} task(s), skipped {skipped}")


    def _view_cookies(self, row: int):
        """Показать cookies задачи (из файла, не из памяти) в удобном JSON."""
        # ЕДИНЫЙ ДОСТУП К ЗАДАЧЕ
        task_id, task = self._get_task(row)
        if not task:
            return

        params = getattr(task, "params", {}) or {}
        url = getattr(task, "url", "") or ""
        cookie_file = params.get("cookie_file")

        try:
            jar, path, loaded = storage.load_cookiejar(url=url, cookie_file=cookie_file)
        except Exception as e:
            self.log._log("ERROR", f"Cookies view({(task_id or '')[:8]}): {e}", "UI")
            QMessageBox.warning(self, "Cookies", f"Failed to load cookies:\n{e}")
            return

        if loaded == 0:
            QMessageBox.information(self, "Cookies", f"No cookies found.\nPath: {path}")
            return

        # ЕДИНЫЙ PRETTY-PRINT
        try:
            data = storage.jar_to_json(jar)
            pretty = self._pretty_json(data)
        except Exception as e:
            self.log._log("WARN", f"jar_to_json failed: {e}", "UI")
            pretty = "Could not serialize cookies."

        title = f"Cookies — {loaded} item(s)"
        head = f"Path: {path}\nLoaded: {loaded}"

        # Для больших наборов — в detailedText, чтобы не подвесить QMessageBox
        dlg = QMessageBox(self)
        dlg.setWindowTitle(title)
        dlg.setIcon(QMessageBox.Information)
        dlg.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
        if len(pretty) > 4000:
            dlg.setText(f"{title}\n{head}\n\n(See details)")
            dlg.setDetailedText(pretty)
        else:
            dlg.setText(f"{title}\n{head}\n\n{pretty}")
        dlg.exec()


        
    # --- ALL TASKS ACTIONS ---

    def _iter_all_task_ids(self) -> list[str]:
        """Вернуть все task_id из менеджера (без зависимости от таблицы)."""
        tm = self.task_manager
        if hasattr(tm, "all_tasks"):
            return [t.id for t in tm.all_tasks()]
        if hasattr(tm, "_tasks"):
            return list(tm._tasks.keys())
        if hasattr(tm, "tasks"):
            return list(tm.tasks.keys())
        return []

    def start_all_tasks(self):
        """Запускает все задачи, которые не RUNNING. Разрешаем повторный старт DONE/FAILED/PENDING/STOPPED."""
        from ui.constants import TaskStatus

        started = errors = 0
        for tid in self._iter_all_task_ids():
            try:
                task = self.task_manager.get_task(tid)
                status = getattr(task, "status", TaskStatus.PENDING)
                if status != TaskStatus.RUNNING:
                    self.task_manager.start_task(tid)
                    started += 1
            except Exception as e:
                errors += 1
                self.log.append_log_line(f"[ERROR] start_all({tid[:8]}): {e}")
        self.log.append_log_line(f"[INFO] Start all: queued {started} task(s), errors {errors}")


    def stop_all_tasks(self):
        """Кооперативно останавливает все RUNNING/PENDING задачи."""
        from ui.constants import TaskStatus

        stopped = errors = 0
        for tid in self._iter_all_task_ids():
            try:
                task = self.task_manager.get_task(tid)
                status = getattr(task, "status", TaskStatus.PENDING)
                if status in {TaskStatus.RUNNING, TaskStatus.PENDING}:
                    self.task_manager.stop_task(tid)
                    stopped += 1
            except Exception as e:
                errors += 1
                self.log.append_log_line(f"[ERROR] stop_all({tid[:8]}): {e}")
        self.log.append_log_line(
            f"[INFO] Stop all: requested stop for {stopped} task(s), errors {errors}")


    def restart_all_tasks(self):
        """
        Перезапуск всех задач:
        - если есть TaskManager.restart_task → используем его;
        - иначе: stop_task (если RUNNING/PENDING) → start_task.
        """
        from ui.constants import TaskStatus  # убедись, что импорт есть вверху

        use_native = hasattr(self.task_manager, "restart_task")
        restarted = errors = 0

        for tid in self._iter_all_task_ids():
            try:
                if use_native:
                    self.task_manager.restart_task(tid)
                else:
                    task = self.task_manager.get_task(tid)
                    status = getattr(task, "status", TaskStatus.PENDING)
                    if status in (TaskStatus.RUNNING, TaskStatus.PENDING):
                        self.task_manager.stop_task(tid)
                    self.task_manager.start_task(tid)
                restarted += 1
            except Exception as e:
                errors += 1
                self.log.append_log_line(f"[ERROR] restart_all({tid[:8]}): {e}")

        self.log.append_log_line(
            f"[INFO] Restart all: requested restart for {restarted} task(s), errors {errors}")

                    
    @Slot()
    def on_start_clicked(self):
        table = self.ui.taskTable
        sel = table.selectionModel()

        if not sel or not sel.hasSelection():
            self.log.append_log_line("[WARN] No tasks selected")
            return

        rows = sorted({idx.row() for idx in sel.selectedRows()})
        if not rows:
            self.log.append_log_line("[WARN] No valid rows selected")
            return

        for row in rows:
            item = table.item(row, Col.URL) # колонка URL
            if not item:
                continue
            task_id = item.data(Qt.UserRole)
            if task_id:
                try:
                    self.task_manager.start_task(task_id)
                    self.log.append_log_line(f"[UI] Start task {task_id[:8]}")
                except Exception as e:
                    self.log.append_log_line(f"[ERROR] start_task({task_id[:8]}): {e}")

    @Slot()
    def on_stop_clicked(self):
        self.log.append_log_line("[UI] Stop clicked")
        self.task_manager.stop_all()
        
    @Slot()
    def on_pause_clicked(self):  # ← добавлено
        ids = self._selected_task_ids()
        if not ids:
            self.log.append_log_line("[WARN] No tasks selected")
            return
        for tid in ids:
            self.task_manager.pause_task(tid)
        self.log.append_log_line(f"[UI] Pause clicked → {len(ids)} task(s)")

    @Slot()
    def on_resume_clicked(self):  # ← добавлено
        ids = self._selected_task_ids()
        if not ids:
            self.log.append_log_line("[WARN] No tasks selected")
            return
        for tid in ids:
            self.task_manager.resume_task(tid)
        self.log.append_log_line(f"[UI] Resume clicked → {len(ids)} task(s)")

    @Slot()
    def on_export_clicked(self):
        # 1) спросить область
        scopes = ["Selected", "Completed", "All"]
        scope, ok = QInputDialog.getItem(self, "Export scope", "Choose:", scopes, 0, False)
        if not ok:
            return
        # 2) делегировать в общий экспорт
        self._export_data(scope)

    @Slot()
    def on_add_task_clicked(self):
        dlg = AddTaskDialog(self)  # наше модальное окно
        if dlg.exec() == QDialog.Accepted and dlg.data:
            data = dlg.data
            self.add_task_row(data["url"], params=data)
            self.log.append("INFO", f"Added task → {data['url']}", tag="UI")


    @Slot()
    def on_delete_clicked(self):
        table = self.ui.taskTable
        sel = table.selectionModel()
        if not sel or not sel.hasSelection():
            self.log.append_log_line("[WARN] Select a row to delete")
            return

        rows = sorted({idx.row() for idx in sel.selectedRows()}, reverse=True)

        for row in rows:
            item = table.item(row, Col.URL)  # колонка с URL и UserRole=task_id
            if not item:
                continue
            task_id = item.data(Qt.UserRole)
            if task_id:
                try:
                    self.task_manager.remove_task(task_id)
                except Exception as e:
                    self.log.append_log_line(f"[ERROR] remove_task({task_id[:8]}): {e}")
            table.removeRow(row)

        self._rebuild_row_index_map()
        self.log.append_log_line(f"[INFO] Deleted {len(rows)} task(s)")

    # ---------- Пересборка индексов ----------
    def _rebuild_row_index_map(self):
        self._row_by_task_id.clear()
        table = self.ui.taskTable
        for row in range(table.rowCount()):
            it = table.item(row, Col.URL)
            if not it:
                continue
            task_id = it.data(Qt.UserRole)
            if task_id:
                self._row_by_task_id[task_id] = row

    # ---------- Обработчики сигналов менеджера ----------
    @Slot(str, str, str)
    def on_task_log(self, task_id: str, level: str, text: str):
        # уровень идёт отдельным аргументом → используем его как фильтр
        self.log.append_log(level, f"[{task_id[:8]}] {text}")

    @Slot(str, str)
    def on_task_status(self, task_id, status):
        row = self._find_row_by_task_id(task_id)
        if row < 0:
            return
        self.set_status_cell(row, status)

    @Slot(str, int)
    def on_task_progress(self, task_id: str, value: int):
        row = self._find_row_by_task_id(task_id)
        if row >= 0:
            base = TaskStatus.RUNNING
            st_item = self.ui.taskTable.item(row, Col.Status) 
            if st_item and st_item.text():
                base = st_item.text().split()[0]
            self.set_status_cell(row, f"{base} {value}%")

    @Slot(str, dict)
    def on_task_result(self, task_id: str, payload: dict):
        from copy import deepcopy

        # Логи — короткий блок
        pretty = self._format_result_short(payload)
        self.log.append_log_line(f"[RESULT][{task_id[:8]}]\n{pretty}")

        row = self._find_row_by_task_id(task_id)
        if row < 0:
            return

        # 1) Сохраняем результат для Data Preview
        self.task_results[row] = deepcopy(payload)

        # 2) Базовые ячейки
        self.set_status_cell(row, TaskStatus.DONE)

        url_val = payload.get("final_url") or payload.get("url") or ""
        if not url_val:
            task = self.task_manager.get_task(task_id)
            if task:
                url_val = getattr(task, "url", "") or url_val
        self.set_url_cell(row, url_val, payload.get("title"))

        self.set_code_cell(row, payload.get("status_code"))

        timings = payload.get("timings", {}) or {}
        self.set_time_cell(row, timings.get("request_ms"))

        # Подсказка по редиректам в статусе
        redirects = payload.get("redirect_chain", []) or []
        st_item = self.ui.taskTable.item(row, Col.Status)
        if st_item:
            st_item.setToolTip(f"{TaskStatus.DONE} • redirects: {len(redirects)}")

        # 3) Cookies по заголовку Set-Cookie
        headers = payload.get("headers", {}) or {}
        low_headers = {k.lower(): v for k, v in headers.items()}
        set_cookie_val = low_headers.get("set-cookie")
        has_cookies = bool(set_cookie_val)
        tip = f"Set-Cookie: {set_cookie_val}" if isinstance(set_cookie_val, str) else ""
        self.set_cookies_cell(row, has_cookies, tip)

        # 4) >>> ЗАПОЛНЯЕМ КОЛОНКУ Results <<<
        self.set_results_cell(row, payload)


        
    def set_results_cell(self, row: int, payload: dict):
        text, tip = "", ""
        if payload:
            redirects = len(payload.get("redirect_chain") or [])
            size = payload.get("content_len") or 0
            code = payload.get("status_code")
            # аккуратный текст без «OK», если кода нет
            code_str = str(code) if code is not None else "—"
            text = f"{code_str} · {size}B · r={redirects}"

            # полный JSON в tooltip (с защитой)
            try:
                import json
                tip = json.dumps(payload, ensure_ascii=False, indent=2)
            except Exception as e:
                tip = f"<failed to build JSON: {e}>"

        it = QTableWidgetItem(text)
        if tip and tip != text:
            it.setToolTip(tip)
        it.setTextAlignment(Qt.AlignCenter)

        self.ui.taskTable.setItem(row, Col.Results, it)
        self.ui.taskTable.resizeRowToContents(row)
        
    def _records_from_rows(self, rows) -> list[dict]:
        records: list[dict] = []
        for row in rows:
            # 1) payload из on_task_result (то, что мы сохраняем для Preview)
            payload = (self.task_results.get(row) if hasattr(self, "task_results") else None)

            # 2) фолбэк — из объекта задачи (если воркер писал self.task.result)
            if not payload:
                task = self._row_to_task(row) if hasattr(self, "_row_to_task") else None
                payload = getattr(task, "result", None) if task else None

            if not payload:
                continue

            rec = deepcopy(payload)
            t = (payload.get("timings") or {})
            rc = payload.get("redirect_chain") or []
            rec.setdefault("final_url", payload.get("final_url") or payload.get("url"))
            rec["request_ms"] = t.get("request_ms")
            rec["redirects"] = len(rc)
            rec.setdefault("status_code", payload.get("status_code"))
            rec.setdefault("title", payload.get("title"))
            rec.setdefault("content_len", payload.get("content_len"))
            records.append(rec)

        # Диагностика в логи
        total_rows = len(rows) if not isinstance(rows, range) else self.ui.taskTable.rowCount()
        self.log.append_log_line(f"[DEBUG] DataPreview: collected {len(records)} record(s) from {total_rows} rows")
        return records

    @Slot(str, str)
    def on_task_error(self, task_id: str, error_str: str):
        self.log.append_log_line(f"[ERROR][{task_id[:8]}] {error_str}")
        
        
    #--------------- CTX ОБРАБОТЧИКИ -------------------#
    
    def _ctx_open_url(self, row: int):
        it = self.ui.taskTable.item(row, Col.URL)
        if not it:
            return
        tip = (it.toolTip() or it.text() or "").strip()
        full_url = tip.split("\n", 1)[0].strip()
        if full_url:
            QDesktopServices.openUrl(QUrl.fromUserInput(full_url))

    def _ctx_copy_url(self, row: int):
        it = self.ui.taskTable.item(row, Col.URL)
        if not it:
            return
        tip = (it.toolTip() or it.text() or "").strip()
        full_url = tip.split("\n", 1)[0].strip()
        if full_url:
            QGuiApplication.clipboard().setText(full_url)
            self.log.append_log_line("[INFO] URL copied to clipboard")

    def _ctx_open_result_folder(self, row: int):
        it = self.ui.taskTable.item(row, Col.Results)
        path = ((it.toolTip() or it.text()) if it else "").strip()
        if not path:
            # фолбэк — попробуем открыть папку экспорта
            base = exporter.default_exports_dir()
            os.makedirs(base, exist_ok=True)
            path = base
        self._open_path(path)

    def _ctx_copy_response_headers(self, row: int):
        # вытащим task_id → task → headers из последнего payload
        task_id, task = self._get_task(row)
        headers = {}
        if task and getattr(task, "result", None):
            headers = (task.result or {}).get("headers", {}) or {}
        if not headers:
            self.log._log("WARN", "No headers available", "UI")
            return
        text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        self._copy_to_clipboard(text, "Headers")


    def _ctx_view_headers_dialog(self, row: int):
        task_id, task = self._get_task(row)
        headers = {}
        if task and getattr(task, "result", None):
            headers = (task.result or {}).get("headers", {}) or {}
        if not headers:
            QMessageBox.information(self, "Headers", "No headers available")
            return

        pretty = self._pretty_json(headers)
        QMessageBox.information(self, "Response Headers", pretty[:6000])


    def _ctx_view_redirects_dialog(self, row: int):
        # унифицированный доступ к задаче
        task_id, task = self._get_task(row)

        redirs = []
        if task and getattr(task, "result", None):
            redirs = (task.result or {}).get("redirect_chain") or []

        if not redirs:
            QMessageBox.information(self, "Redirects", "No redirects")
            return

        # аккуратно пронумеруем хопы
        lines = []
        for i, hop in enumerate(redirs, 1):
            code = hop.get("status_code", "")
            url = hop.get("url") or hop.get("location") or ""
            lines.append(f"{i}. {code} → {url}")

        text = "\n".join(lines)
        QMessageBox.information(self, "Redirect history", text[:6000])


    def _ctx_view_cookies_dialog(self, row: int):
        task_id, task = self._get_task(row)
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
        # 🔁 Единая выборка задачи по строке (без приватных полей/магических индексов)
        task_id, task = self._get_task(row)
        if not task_id or not task:
            self.log._log("WARN", f"No task found for row {row}", "UI")
            return

        current = dict(getattr(task, "params", {}) or {})
        url = getattr(task, "url", "")

        dlg = ParamsDialog(self, initial=current, task_url=url)

        # Новый путь: если у диалога есть сигналы — пользуемся ими
        if hasattr(dlg, "applied"):
            dlg.applied.connect(
                lambda params, r=row, tid=task_id: self._on_params_applied_ctx(r, tid, params, run=False)
            )
        if hasattr(dlg, "applied_and_run"):
            dlg.applied_and_run.connect(
                lambda params, r=row, tid=task_id: self._on_params_applied_ctx(r, tid, params, run=True)
            )

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
            self.log.append_log_line(f"[ERROR] update_task_params({task_id[:8]}): {e}")
            return

        # обновить ячейку Params (иконка ⚙ + tooltip)
        light = {k: params.get(k) for k in ("method","proxy","user_agent","timeout","retries") if params.get(k)}
        try:
            self.set_params_cell(row, bool(light), str(light) if light else "")
        except Exception:
            pass

        self.log.append_log_line(f"[INFO] Params updated for {task_id[:8]}")

        # Apply & Run → безопасный перезапуск
        if run:
            # если есть нативный метод — используем его
            if getattr(self.task_manager, "restart_task", None):
                try:
                    self.task_manager.restart_task(task_id)
                    self.log.append_log_line(f"[INFO] Task restarted with new params ({task_id[:8]})")
                    return
                except Exception as e:
                    self.log.append_log_line(f"[WARN] restart_task failed: {e}")
            # fallback: стоп (если бежит) → старт
            try:
                self.task_manager.stop_task(task_id)
            except Exception:
                pass
            try:
                self.task_manager.start_task(task_id)
                self.log.append_log_line(f"[INFO] Task started with new params ({task_id[:8]})")
            except Exception as e:
                self.log.append_log_line(f"[ERROR] start_task({task_id[:8]}): {e}")