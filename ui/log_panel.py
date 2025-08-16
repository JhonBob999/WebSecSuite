from typing import Set, List, Tuple, Optional, Iterable
from PySide6.QtWidgets import QPlainTextEdit, QTextEdit, QLineEdit, QCheckBox, QLabel, QPushButton
from PySide6.QtGui import QKeySequence, QTextCursor, QShortcut
from PySide6.QtCore import QDateTime, QRegularExpression

class LogPanel:
    # максимум строк, хранимых в буфере (для экспорта/поиска и т.п.)
    MAX_LOG_LINES = 100_000

    def __init__(
        self,
        text_edit: QPlainTextEdit | QTextEdit,
        line_edit: Optional[QLineEdit] = None,
        *,
        cb_case: Optional[QCheckBox] = None,
        cb_regex: Optional[QCheckBox] = None,
        cb_whole: Optional[QCheckBox] = None,
        counter_label: Optional[QLabel] = None,
        export_btn: Optional[QPushButton] = None,
        root_dir: str = "data/logs"
    ):
        self.text_edit = text_edit
        self.root_dir = root_dir

        # фильтр уровней (оставляем как было)
        self.log_filter: Set[str] = {"INFO", "WARN", "ERROR"}   # какие уровни выводим в виджет
        self.log_buffer: List[Tuple[str, str, str]] = []        # (ts, level, f"[TAG] msg" или просто msg)

        # поиск/навигация
        self._matches: list[tuple[int, int]] = []
        self._match_idx: int = -1

        # виджеты поиска/навигации
        self._line_edit: Optional[QLineEdit] = line_edit
        self._cb_case: Optional[QCheckBox] = cb_case
        self._cb_regex: Optional[QCheckBox] = cb_regex
        self._cb_whole: Optional[QCheckBox] = cb_whole
        self._counter: Optional[QLabel] = counter_label
        self._export_btn: Optional[QPushButton] = export_btn

        # хайлайтер
        from ui.log_highlighter import LogHighlighter
        self._highlighter = LogHighlighter(self.text_edit.document())

        # сигналы поиска
        if self._line_edit:
            self._line_edit.textChanged.connect(self._on_filter_changed)
        if self._cb_case:
            self._cb_case.toggled.connect(self._on_flags_changed)
        if self._cb_regex:
            self._cb_regex.toggled.connect(self._on_flags_changed)
        if self._cb_whole:
            self._cb_whole.toggled.connect(self._on_flags_changed)

        # кнопка экспорта (если пробрасываешь её сюда)
        if self._export_btn:
            self._export_btn.clicked.connect(lambda: self.export_matches(to_json=False))

        # хоткеи вешаем на text_edit
        QShortcut(QKeySequence("F3"),       self.text_edit, activated=self.navigate_next)
        QShortcut(QKeySequence("Shift+F3"), self.text_edit, activated=self.navigate_prev)
        QShortcut(QKeySequence("Ctrl+E"),   self.text_edit, activated=getattr(self, "export_matches", lambda: None))

        # первичная инициализация поиска (пустая строка)
        try:
            self._highlighter.set_search("", regex_mode=False, case_sensitive=False, whole_word=False)
        except Exception:
            pass
        if self._counter:
            self._counter.setText("0 / 0")



    # --- публичные удобные методы ----------------------------------------

    def clear(self) -> None:
        # 1) очистка текста и буфера
        self.text_edit.clear()
        self.text_edit.moveCursor(QTextCursor.Start)
        self.log_buffer.clear()

        # 2) сброс виджетов поиска (без лишних сигналов)
        if self._line_edit:
            self._line_edit.blockSignals(True)
            self._line_edit.clear()
            self._line_edit.blockSignals(False)

        if self._cb_case:
            self._cb_case.blockSignals(True)
            self._cb_case.setChecked(False)
            self._cb_case.blockSignals(False)

        if self._cb_regex:
            self._cb_regex.blockSignals(True)
            self._cb_regex.setChecked(False)
            self._cb_regex.blockSignals(False)

        if self._cb_whole:
            self._cb_whole.blockSignals(True)
            self._cb_whole.setChecked(False)
            self._cb_whole.blockSignals(False)

        # 3) сброс подсветки/совпадений
        try:
            # унифицированный сброс состояния поиска у хайлайтера
            self._highlighter.set_search("", regex_mode=False, case_sensitive=False, whole_word=False)
        except Exception:
            pass

        self._matches.clear()
        self._match_idx = -1

        # 4) счётчик
        if self._counter:
            self._counter.setText("0 / 0")


    def set_filter(self, levels: Iterable[str]) -> None:
        """Задать уровни, которые будут отображаться в виджете (буфер пишется всегда)."""
        self.log_filter = {str(l).upper() for l in levels}
        
    def _on_flags_changed(self, _checked: bool):
        # читаем текущий текст из поля поиска, если оно подключено
        text = self._line_edit.text().strip() if self._line_edit else ""
        self._apply_search(text)


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

    def _on_filter_changed(self, text: str):
        text = text or ""

        # флаги из чекбоксов
        regex_mode = bool(self._cb_regex.isChecked()) if self._cb_regex else False
        case_sensitive = bool(self._cb_case.isChecked()) if self._cb_case else False
        whole_word = bool(self._cb_whole.isChecked()) if self._cb_whole else False

        # 1) Пытаемся делегировать в хайлайтер (предпочтительно)
        highlighter = getattr(self, "_highlighter", None) or getattr(self.text_edit.document(), "highlighter", None)
        if highlighter and hasattr(highlighter, "set_search"):
            try:
                highlighter.set_search(
                    text,
                    regex_mode=regex_mode,
                    case_sensitive=case_sensitive,
                    whole_word=whole_word,
                )
                count = int(getattr(highlighter, "match_count", 0))
                self._matches.clear()
                self._match_idx = -1
                if self._counter:
                    self._counter.setText(f"0 / {count}" if count else "0 / 0")
                return
            except Exception:
                # если что-то пошло не так — тихо проваливаемся во фолбэк
                pass

        # 2) Фолбэк: простой поиск по тексту/регэкспу вручную
        self._matches.clear()
        self._match_idx = -1

        if not text:
            if self._counter:
                self._counter.setText("0 / 0")
            return

        doc = self.text_edit.document()
        doc_text = doc.toPlainText()

        # собираем паттерн с учётом флагов
        if regex_mode:
            pattern = text
            if whole_word:
                pattern = r"\b(?:%s)\b" % pattern
        else:
            pattern = QRegularExpression.escape(text)
            if whole_word:
                pattern = r"\b%s\b" % pattern

        rx = QRegularExpression(pattern)
        rx.setPatternOptions(
            QRegularExpression.NoPatternOption if case_sensitive
            else QRegularExpression.CaseInsensitiveOption
        )

        pos = 0
        while True:
            m = rx.match(doc_text, pos)
            if not m.hasMatch():
                break
            start, end = m.capturedStart(), m.capturedEnd()
            cur = QTextCursor(doc)
            cur.setPosition(start)
            cur.setPosition(end, QTextCursor.KeepAnchor)
            self._matches.append(cur)
            # защита от зацикливания при пустых матчах
            pos = end if end > pos else pos + 1

        # Обновляем счётчик и ставим курсор на первое совпадение (если есть)
        total = len(self._matches)
        if self._counter:
            self._counter.setText(f"1 / {total}" if total else "0 / 0")
        if total:
            self._match_idx = 0
            self.text_edit.setTextCursor(self._matches[0])
            self.text_edit.ensureCursorVisible()


    def navigate_prev(self):
        # 1) Пытаемся делегировать в хайлайтер
        highlighter = getattr(self, "_highlighter", None) or getattr(self.text_edit.document(), "highlighter", None)
        if highlighter and hasattr(highlighter, "prev_match"):
            try:
                idx, total = highlighter.prev_match()
                if total > 0 and idx >= 0:
                    self._apply_range_idx(idx)
                    if self._counter:
                        self._counter.setText(f"{idx + 1} / {total}")
                    return
            except Exception:
                pass

        # 2) Фолбэк на локальные курсоры
        if not self._matches:
            return
        self._match_idx = (self._match_idx - 1) % len(self._matches)
        self._apply_current_match()

    def navigate_next(self):
        # 1) Пытаемся делегировать в хайлайтер
        highlighter = getattr(self, "_highlighter", None) or getattr(self.text_edit.document(), "highlighter", None)
        if highlighter and hasattr(highlighter, "next_match"):
            try:
                idx, total = highlighter.next_match()
                if total > 0 and idx >= 0:
                    self._apply_range_idx(idx)
                    if self._counter:
                        self._counter.setText(f"{idx + 1} / {total}")
                    return
            except Exception:
                pass

        # 2) Фолбэк на локальные курсоры
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
        
    def _current_search_flags(self):
        return {
            "regex_mode": bool(self._cb_regex.isChecked()) if self._cb_regex else False,
            "case_sensitive": bool(self._cb_case.isChecked()) if self._cb_case else False,
            "whole_word": bool(self._cb_whole.isChecked()) if self._cb_whole else False,
        }
        
    def _apply_search(self, text: str):
        flags = self._current_search_flags()
        try:
            self._highlighter.set_search(text, **flags)
            total = getattr(self._highlighter, "match_count", 0)
            if self.counter:
                self.counter.setText(f"0 / {total}" if total else "0 / 0")
            # сбрасываем локальный fallback (на всякий)
            self._matches = []
            self._match_idx = -1
        except Exception:
            # в крайнем случае можно оставить твой fallback, если он у тебя есть
            pass
        
        
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
        
        
    def _apply_range_idx(self, idx: int):
        """Позиционирование курсора по диапазону из хайлайтера."""
        try:
            ranges = self._highlighter.get_match_ranges()
            if not ranges:
                return
            start, end = ranges[idx]
            cur = QTextCursor(self.text_edit.document())
            cur.setPosition(int(start))
            cur.setPosition(int(end), QTextCursor.KeepAnchor)
            self.text_edit.setTextCursor(cur)
            self.text_edit.ensureCursorVisible()
        except Exception:
            pass
        
    def _nav_step(self, step: int):
        # step: +1 = F3, -1 = Shift+F3
        try:
            idx, total = (self._highlighter.next_match() if step > 0 else self._highlighter.prev_match())
            if total > 0 and idx >= 0:
                self._apply_range_idx(idx)
                if self.counter:
                    self.counter.setText(f"{idx + 1} / {total}")
        except Exception:
            pass


    def _try_delegate_navigation(self, step: int) -> bool:
        try:
            if step > 0:
                idx, total = self._highlighter.next_match()
            else:
                idx, total = self._highlighter.prev_match()
            if total <= 0 or idx < 0:
                return True  # делегировали, но совпадений нет
            self._apply_range_idx(idx)
            if self._counter:
                self._counter.setText(f"{idx + 1} / {total}")
            return True
        except Exception:
            return False


