# ui/log_panel.py
from __future__ import annotations
from typing import Iterable, Set, Tuple, List
from PySide6.QtCore import QDateTime, QRegularExpression
from PySide6.QtGui import QTextCursor, QShortcut, QKeySequence
from PySide6.QtWidgets import QPlainTextEdit, QTextEdit


class LogPanel:
    # максимум строк, хранимых в буфере (для экспорта/поиска и т.п.)
    MAX_LOG_LINES = 100_000

    def __init__(self, text_edit: QPlainTextEdit | QTextEdit):
        self.text_edit = text_edit
        self.log_filter: Set[str] = {"INFO", "WARN", "ERROR"}  # какие уровни выводим в виджет
        self.log_buffer: List[Tuple[str, str, str]] = []       # (ts, level, f"[TAG] msg" или просто msg)
        self._matches = []
        self._match_idx = -1
        
        # виджеты фильтра подключим отдельно через set_filter_widgets(...)
        self._line_edit = None
        self._btn_prev = None
        self._btn_next = None
        self._counter = None
        self._export_btn = None
        
        # хоткеи вешаем на text_edit
        QShortcut(QKeySequence("F3"),       self.text_edit, activated=self.navigate_next)
        QShortcut(QKeySequence("Shift+F3"), self.text_edit, activated=self.navigate_prev)
        QShortcut(QKeySequence("Ctrl+E"),   self.text_edit, activated=self.export_matches if hasattr(self, "export_matches") else (lambda: None))


    # --- публичные удобные методы ----------------------------------------

    def clear(self) -> None:
        self.text_edit.clear()
        self.log_buffer.clear()

    def set_filter(self, levels: Iterable[str]) -> None:
        """Задать уровни, которые будут отображаться в виджете (буфер пишется всегда)."""
        self.log_filter = {str(l).upper() for l in levels}

    # Доп. сахар: единый короткий вызов
    def append(self, level: str, text: str, tag: str | None = None) -> None:
        self._log(level, text, tag or "")

    # --- ТВОИ МЕТОДЫ (перенесены как есть, внутри адаптированы под text_edit) ---

    def append_log(self, level: str, text: str):
        ts = QDateTime.currentDateTime().toString("HH:mm:ss")
        line = f"[{ts}] [{level}] {text}"
        # прямой вывод в виджет без буфера (оставляем твой поведенческий контракт)
        self.text_edit.appendPlainText(line)

    # Обновлённый шим совместимости
    def append_log_line(self, text: str) -> None:
        raw = str(text or "")
        lvl = "INFO"
        body = raw
        if raw.startswith("[WARN]"):
            lvl, body = "WARN", raw[6:].lstrip()
        elif raw.startswith("[ERROR]"):
            lvl, body = "ERROR", raw[7:].lstrip()
        elif raw.startswith("[INFO]"):
            lvl, body = "INFO", raw[6:].lstrip()
        # поддержка кастомных тэгов вроде [UI], [RESULT]
        tag = ""
        if body.startswith("[") and "]" in body[:16]:
            tag = body[1:body.index("]")]
            body = body[len(tag) + 2:].lstrip()
        self._log(lvl, body, tag)

    # --- Unified logger API ----------------------------------------------
    def _log(self, level: str, msg: str, tag: str = "") -> None:
        """
        Единый логгер: формат [HH:MM:SS] [LEVEL][TAG] message
        level: INFO|WARN|ERROR
        tag:   опционально, например 'UI' или 'RESULT'
        """
        level = (level or "INFO").upper()
        if level not in {"INFO", "WARN", "ERROR"}:
            level = "INFO"
        ts = QDateTime.currentDateTime().toString("HH:mm:ss")
        tag_part = f"[{tag}]" if tag else ""
        line = f"[{ts}] [{level}]{tag_part} {msg}"

        # буфер (для экспорта/поиска)
        self.log_buffer.append((ts, level, f"{tag_part} {msg}".strip()))
        if len(self.log_buffer) > self.MAX_LOG_LINES:
            del self.log_buffer[:1000]

        # вывод в виджет по фильтру уровней
        if level in self.log_filter:
            cursor = self.text_edit.textCursor()
            cursor.movePosition(QTextCursor.End)
            cursor.insertText(line + "\n")
            self.text_edit.setTextCursor(cursor)
            self.text_edit.ensureCursorVisible()
            
            
    def set_filter_widgets(self, line_edit, btn_prev=None, btn_next=None, counter_label=None, export_button=None):
        self._line_edit = line_edit
        self._btn_prev = btn_prev
        self._btn_next = btn_next
        self._counter = counter_label
        self._export_btn = export_button

        # состояние поиска (fallback-навигатор)
        self._matches = []
        self._match_idx = -1

        if self._line_edit:
            self._line_edit.textChanged.connect(self._on_filter_changed)
        if self._btn_prev:
            self._btn_prev.clicked.connect(self.navigate_prev)
        if self._btn_next:
            self._btn_next.clicked.connect(self.navigate_next)
        if self._export_btn and hasattr(self, "export_matches"):
            self._export_btn.clicked.connect(self.export_matches)

    def _on_filter_changed(self, text: str):
        text = text or ""

        # если твой LogHighlighter умеет set_search/text → делегируем
        highlighter = getattr(self.text_edit.document(), "highlighter", None)
        if highlighter and hasattr(highlighter, "set_search"):
            try:
                highlighter.set_search(text)
                count = int(getattr(highlighter, "match_count", 0))
                self._matches.clear()
                self._match_idx = -1
                if self._counter:
                    self._counter.setText(f"0 / {count}" if count else "0 / 0")
                return
            except Exception:
                pass

        # fallback: ищем сами
        self._matches.clear()
        self._match_idx = -1
        if not text:
            if self._counter:
                self._counter.setText("0 / 0")
            return

        doc_text = self.text_edit.document().toPlainText()
        rx = QRegularExpression(QRegularExpression.escape(text))
        pos = 0
        while True:
            m = rx.match(doc_text, pos)
            if not m.hasMatch():
                break
            start, end = m.capturedStart(), m.capturedEnd()
            cur = QTextCursor(self.text_edit.document())
            cur.setPosition(start)
            cur.setPosition(end, QTextCursor.KeepAnchor)
            self._matches.append(cur)
            pos = end

        if self._counter:
            self._counter.setText(f"0 / {len(self._matches)}" if self._matches else "0 / 0")

    def navigate_prev(self):
        if self._try_delegate_navigation(-1):
            return
        if not self._matches:
            return
        self._match_idx = (self._match_idx - 1) % len(self._matches)
        self._apply_current_match()

    def navigate_next(self):
        if self._try_delegate_navigation(+1):
            return
        if not self._matches:
            return
        self._match_idx = (self._match_idx + 1) % len(self._matches)
        self._apply_current_match()

    def _apply_current_match(self):
        cur = self._matches[self._match_idx]
        self.text_edit.setTextCursor(cur)
        self.text_edit.ensureCursorVisible()
        if self._counter:
            self._counter.setText(f"{self._match_idx + 1} / {len(self._matches)}")

    def _try_delegate_navigation(self, step: int) -> bool:
        highlighter = getattr(self.text_edit.document(), "highlighter", None)
        if not highlighter:
            return False
        try:
            if step > 0 and hasattr(highlighter, "next_match"):
                idx, total = highlighter.next_match()
            elif step < 0 and hasattr(highlighter, "prev_match"):
                idx, total = highlighter.prev_match()
            else:
                return False
            if self._counter:
                self._counter.setText(f"{(idx + 1) if total else 0} / {total}")
            return True
        except Exception:
            return False
        
        
    def export_matches(self):
        """Экспорт совпадений текущего поиска в TXT/JSON → data/exports/."""
        from PySide6.QtWidgets import QFileDialog
        from PySide6.QtGui import QDesktopServices
        from PySide6.QtCore import QDateTime, QUrl
        from pathlib import Path
        import json
        import bisect

        # 1) Проверка поиска
        query = ""
        if hasattr(self, "_line_edit") and self._line_edit:
            query = self._line_edit.text() or ""
        if not query:
            self.append("WARN", "No search query to export", "LOG")
            return

        # 2) Собираем совпадения
        # Предпочитаем готовый список курсоров из fallback-поиска
        matches = list(getattr(self, "_matches", []) or [])
        # Если свой список пуст, но хайлайтер умеет отдавать диапазоны — попробуем делегирование
        if not matches:
            highlighter = getattr(self.text_edit.document(), "highlighter", None)
            get_ranges = getattr(highlighter, "get_match_ranges", None)
            if callable(get_ranges):
                try:
                    ranges = get_ranges()  # ожидается: list[(start, end)]
                    from PySide6.QtGui import QTextCursor
                    doc = self.text_edit.document()
                    for (start, end) in ranges:
                        cur = QTextCursor(doc)
                        cur.setPosition(int(start))
                        cur.setPosition(int(end), QTextCursor.KeepAnchor)
                        matches.append(cur)
                except Exception:
                    pass

        if not matches:
            self.append("WARN", "No matches found to export", "LOG")
            return

        # 3) Преобразуем в [(line_no, line_text)]
        doc_text = self.text_edit.document().toPlainText()
        # Предрассчёт стартов строк для быстрого маппинга позиций в номер строки
        line_starts = [0]
        for i, ch in enumerate(doc_text):
            if ch == "\n":
                line_starts.append(i + 1)
        # добавим фиктивный конец
        line_starts.append(len(doc_text) + 1)

        rows = []
        for cur in matches:
            start_pos = cur.selectionStart()
            # индекс строки: правый старт <= start_pos
            idx = bisect.bisect_right(line_starts, start_pos) - 1
            if idx < 0:
                idx = 0
            line_no = idx + 1  # человеко-понятная нумерация с 1
            line_start = line_starts[idx]
            line_end = line_starts[idx + 1] - 1
            line_text = doc_text[line_start:line_end].rstrip("\r\n")
            rows.append((line_no, line_text))

        # 4) Диалог сохранения
        ts = QDateTime.currentDateTime().toString("yyyyMMdd_HHmmss")
        base = Path("data/exports")
        base.mkdir(parents=True, exist_ok=True)
        default_name = base / f"log_search_{ts}.txt"

        file_path, _ = QFileDialog.getSaveFileName(
            None,
            "Export log matches",
            str(default_name),
            "Text (*.txt);;JSON (*.json)"
        )
        if not file_path:
            return

        # 5) Запись файла
        try:
            if file_path.lower().endswith(".json"):
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(
                        [{"line_no": n, "text": t} for (n, t) in rows],
                        f, ensure_ascii=False, indent=2
                    )
            else:
                # по умолчанию TXT
                with open(file_path, "w", encoding="utf-8") as f:
                    for n, t in rows:
                        f.write(f"[{n}] {t}\n")
        except Exception as e:
            self.append("ERROR", f"Export failed: {e}", "LOG")
            return

        # 6) Сообщение и открытие папки
        self.append("INFO", f"Exported {len(rows)} matches → {file_path}", "LOG")
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(file_path).parent)))

