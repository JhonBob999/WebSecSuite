from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QColor, QFont, QGuiApplication, QTextCharFormat, QTextCursor, QTextFormat
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QMenu,
    QPlainTextEdit,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class UniversalViewerDialog(QDialog):
    def __init__(
        self,
        title="Viewer",
        payload=None,
        content=None,
        parent=None,
        show_summary=False,
        save_dialog_title="Save Results",
        default_save_stem="results",
    ):
        super().__init__(parent)
        self._payload = payload
        self._content = content
        self._pretty_mode = True
        self._search_matches: list[int] = []
        self._current_match_index = -1
        self._jumped_line_number = None
        self._save_dialog_title = save_dialog_title
        self._default_save_stem = default_save_stem

        self.setWindowTitle(title)
        self.setMinimumSize(720, 480)
        self.setSizeGripEnabled(True)
        self.resize(980, 640)

        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        self.summary_label = None
        if show_summary:
            summary_box = QWidget(self)
            summary_layout = QVBoxLayout(summary_box)
            summary_layout.setContentsMargins(8, 8, 8, 8)
            summary_layout.setSpacing(2)
            self.summary_label = QLabel(self._build_summary_text(payload), self)
            self.summary_label.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
            self.summary_label.setWordWrap(True)
            summary_layout.addWidget(self.summary_label)
            root.addWidget(summary_box)

        search_row = QHBoxLayout()
        search_row.setSpacing(6)
        self.search_label = QLabel("Search:", self)
        self.search_input = QLineEdit(self)
        self.search_input.setPlaceholderText("Find in current results...")
        self.search_input.setClearButtonEnabled(True)
        self.btn_prev = QPushButton("Prev", self)
        self.btn_next = QPushButton("Next", self)
        self.btn_copy_match = QPushButton("Copy Match", self)
        self.btn_export_matches = QPushButton("Export Matches", self)
        self.search_counter = QLabel("0 / 0", self)
        self.line_jump_input = QSpinBox(self)
        self.line_jump_input.setRange(1, 1)
        self.line_jump_input.setPrefix("Line ")
        self.line_jump_input.setFixedWidth(92)
        self.btn_jump_line = QPushButton("Go", self)
        search_row.addWidget(self.search_label)
        search_row.addWidget(self.search_input, 1)
        search_row.addWidget(self.btn_prev)
        search_row.addWidget(self.btn_next)
        search_row.addWidget(self.btn_copy_match)
        search_row.addWidget(self.btn_export_matches)
        search_row.addWidget(self.search_counter)
        search_row.addSpacing(8)
        search_row.addWidget(self.line_jump_input)
        search_row.addWidget(self.btn_jump_line)
        root.addLayout(search_row)

        self.viewer = QPlainTextEdit(self)
        self.viewer.setReadOnly(True)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.Monospace)
        self.viewer.setFont(mono)
        self.viewer.setContextMenuPolicy(Qt.CustomContextMenu)
        self.viewer.customContextMenuRequested.connect(self._show_editor_context_menu)
        root.addWidget(self.viewer, 1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        self.btn_copy = QPushButton("Copy", self)
        self.btn_pretty = QPushButton("Pretty JSON", self)
        self.btn_raw = QPushButton("Raw JSON", self)
        self.btn_save = QPushButton("Save to file", self)
        self.line_count_label = QLabel("Lines: 0", self)
        self.btn_close = QPushButton("Close", self)
        btn_row.addWidget(self.btn_copy)
        btn_row.addWidget(self.btn_pretty)
        btn_row.addWidget(self.btn_raw)
        btn_row.addWidget(self.btn_save)
        btn_row.addWidget(self.line_count_label)
        btn_row.addStretch(1)
        btn_row.addWidget(self.btn_close)
        root.addLayout(btn_row)

        self.btn_copy.clicked.connect(self._copy_current_text)
        self.btn_pretty.clicked.connect(self._show_pretty_json)
        self.btn_raw.clicked.connect(self._show_raw_json)
        self.btn_save.clicked.connect(self._save_to_file)
        self.btn_close.clicked.connect(self.close)
        self.search_input.textChanged.connect(self._rebuild_search_index)
        self.search_input.returnPressed.connect(self._goto_next_match)
        self.search_input.installEventFilter(self)
        self.btn_next.clicked.connect(self._goto_next_match)
        self.btn_prev.clicked.connect(self._goto_prev_match)
        self.btn_copy_match.clicked.connect(self._copy_current_match_line)
        self.btn_export_matches.clicked.connect(self._export_search_matches)
        self.btn_jump_line.clicked.connect(self._jump_to_line)
        self.line_jump_input.lineEdit().returnPressed.connect(self._jump_to_line)

        self._refresh_text()

    def eventFilter(self, watched, event):
        if (
            watched is self.search_input
            and event.type() == QEvent.KeyPress
            and event.key() in (Qt.Key_Return, Qt.Key_Enter)
            and (event.modifiers() & Qt.ShiftModifier)
        ):
            self._goto_prev_match()
            return True
        return super().eventFilter(watched, event)

    def _build_summary_text(self, payload) -> str:
        if not isinstance(payload, dict):
            return "URL: —\nfinal_url: —\nstatus_code: —\ntime/request_ms: —"

        url = payload.get("url") or "—"
        final_url = payload.get("final_url") or "—"
        status = payload.get("status_code")
        timings = payload.get("timings") if isinstance(payload.get("timings"), dict) else {}
        request_ms = timings.get("request_ms")
        t_val = payload.get("time")
        time_val = request_ms if request_ms is not None else t_val
        return (
            f"URL: {url}\n"
            f"final_url: {final_url}\n"
            f"status_code: {status if status is not None else '—'}\n"
            f"time/request_ms: {time_val if time_val is not None else '—'}"
        )

    def _json_text(self, pretty: bool) -> str:
        data = self._content if self._content is not None else self._payload
        if data in (None, "", {}, []):
            return "No results available"
        if isinstance(data, (dict, list)):
            return json.dumps(data, ensure_ascii=False, indent=2 if pretty else None)
        if isinstance(data, str):
            stripped = data.strip()
            if not stripped:
                return "No results available"
            try:
                obj = json.loads(stripped)
                return json.dumps(obj, ensure_ascii=False, indent=2 if pretty else None)
            except Exception:
                return data
        try:
            return repr(data)
        except Exception:
            return "No results available"

    def _refresh_text(self):
        self._jumped_line_number = None
        self.viewer.setPlainText(self._json_text(pretty=self._pretty_mode))
        self._update_line_count()
        self._rebuild_search_index()

    def _update_line_count(self):
        total_lines = max(1, self.viewer.blockCount())
        self.line_count_label.setText(f"Lines: {total_lines}")
        self.line_jump_input.setMaximum(total_lines)

    def _focus_line_jump(self):
        self.line_jump_input.setFocus(Qt.ShortcutFocusReason)
        self.line_jump_input.selectAll()

    def _jump_to_line(self):
        total_lines = max(1, self.viewer.blockCount())
        line_number = min(max(1, self.line_jump_input.value()), total_lines)
        if line_number != self.line_jump_input.value():
            self.line_jump_input.setValue(line_number)

        block = self.viewer.document().findBlockByNumber(line_number - 1)
        if not block.isValid():
            return

        cursor = QTextCursor(block)
        self.viewer.setTextCursor(cursor)
        self.viewer.centerCursor()
        self._jumped_line_number = line_number
        self._apply_current_highlights(self._current_search_highlight_selections())
        self.viewer.setFocus(Qt.ShortcutFocusReason)

    def _show_pretty_json(self):
        self._pretty_mode = True
        self._refresh_text()

    def _show_raw_json(self):
        self._pretty_mode = False
        self._refresh_text()

    def _copy_current_text(self):
        cursor = self.viewer.textCursor()
        if cursor.hasSelection():
            selected_text = cursor.selectedText().replace("\u2029", "\n")
            QGuiApplication.clipboard().setText(selected_text)
            return
        QGuiApplication.clipboard().setText(self.viewer.toPlainText() or "")

    def _show_editor_context_menu(self, position):
        cursor = self.viewer.textCursor()
        menu = QMenu(self.viewer)

        copy_selected = menu.addAction("Copy selected")
        copy_selected.setEnabled(cursor.hasSelection())
        copy_selected.triggered.connect(self._copy_selected_text)

        menu.addAction("Copy all", self._copy_all_text)
        menu.addAction("Select all", self.viewer.selectAll)
        menu.addSeparator()
        menu.addAction("Copy current match", self._copy_current_match_line)
        menu.addAction("Jump to line...", self._focus_line_jump)
        menu.addAction("Save to file", self._save_to_file)
        menu.addAction("Export search matches", self._export_search_matches)
        menu.exec(self.viewer.mapToGlobal(position))

    def _copy_selected_text(self):
        cursor = self.viewer.textCursor()
        if not cursor.hasSelection():
            return
        selected_text = cursor.selectedText().replace("\u2029", "\n")
        QGuiApplication.clipboard().setText(selected_text)

    def _copy_all_text(self):
        QGuiApplication.clipboard().setText(self.viewer.toPlainText() or "")

    def _line_for_offset(self, text: str, offset: int):
        if offset < 0 or offset > len(text):
            return None
        line_start = text.rfind("\n", 0, offset) + 1
        line_end = text.find("\n", offset)
        if line_end == -1:
            line_end = len(text)
        return text[line_start:line_end].rstrip("\r")

    def _current_match_line(self):
        query = (self.search_input.text() or "").strip()
        text = self.viewer.toPlainText() or ""
        if (
            not query
            or not text
            or not self._search_matches
            or self._current_match_index < 0
            or self._current_match_index >= len(self._search_matches)
        ):
            return None
        return self._line_for_offset(text, self._search_matches[self._current_match_index])

    def _copy_current_match_line(self):
        line = self._current_match_line()
        if line is None:
            QMessageBox.information(self, "Copy Match", "No current search match to copy.")
            return
        QGuiApplication.clipboard().setText(line)

    def _save_to_file(self):
        default_name = f"{self._default_save_stem}.json" if self._pretty_mode else f"{self._default_save_stem}.txt"
        default_path = str(Path("data") / "exports" / default_name)
        path, _ = QFileDialog.getSaveFileName(
            self,
            self._save_dialog_title,
            default_path,
            "JSON files (*.json);;Text files (*.txt);;All files (*)",
        )
        if not path:
            return
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(self.viewer.toPlainText() or "", encoding="utf-8")
        except Exception as e:
            QMessageBox.warning(self, "Save failed", f"Could not save file:\n{e}")

    def _collect_search_match_lines(self):
        query = (self.search_input.text() or "").strip()
        text = self.viewer.toPlainText() or ""
        if not query or not text or not self._search_matches:
            return query, []

        matches = []
        match_index = 0
        line_start = 0
        sorted_offsets = sorted(pos for pos in self._search_matches if pos >= 0)
        lines = text.splitlines(keepends=True)

        for line_number, line in enumerate(lines, start=1):
            line_end = line_start + len(line)
            display_line = line.rstrip("\r\n")
            while match_index < len(sorted_offsets) and sorted_offsets[match_index] < line_end:
                matches.append((line_number, display_line))
                match_index += 1
            line_start = line_end

        if match_index < len(sorted_offsets):
            fallback_lines = text.splitlines()
            line_number = max(1, len(fallback_lines))
            line_text = fallback_lines[-1] if fallback_lines else ""
            for _ in sorted_offsets[match_index:]:
                matches.append((line_number, line_text))
        return query, matches

    def _format_search_matches_export(self, query, matches) -> str:
        lines = [
            f"Viewer: {self.windowTitle()}",
            f"Search query: {query}",
            f"Total matches: {len(matches)}",
            "",
        ]
        for index, (line_number, line_text) in enumerate(matches, start=1):
            lines.append(f"[{index}] line {line_number}")
            lines.append(line_text)
            lines.append("")
        return "\n".join(lines)

    def _export_search_matches(self):
        query, matches = self._collect_search_match_lines()
        if not query or not matches:
            QMessageBox.information(self, "Export Search Matches", "No search matches to export.")
            return

        default_path = str(Path("data") / "exports" / f"{self._default_save_stem}_matches.txt")
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Search Matches",
            default_path,
            "Text files (*.txt);;All files (*)",
        )
        if not path:
            return
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(self._format_search_matches_export(query, matches), encoding="utf-8")
        except Exception as e:
            QMessageBox.warning(self, "Export failed", f"Could not export search matches:\n{e}")

    def _rebuild_search_index(self):
        query = (self.search_input.text() or "").strip()
        text = self.viewer.toPlainText() or ""
        self._jumped_line_number = None
        self._search_matches = []
        self._current_match_index = -1
        self._apply_current_highlights()

        if not query or not text:
            self._update_search_counter()
            return

        lower_text = text.lower()
        lower_query = query.lower()
        start = 0
        while True:
            pos = lower_text.find(lower_query, start)
            if pos == -1:
                break
            self._search_matches.append(pos)
            start = pos + len(lower_query)

        if self._search_matches:
            self._current_match_index = 0
            self._apply_current_match()
        else:
            self._update_search_counter()

    def _apply_current_match(self):
        query = (self.search_input.text() or "").strip()
        text = self.viewer.toPlainText() or ""
        if (
            not query
            or not text
            or not self._search_matches
            or self._current_match_index < 0
            or self._current_match_index >= len(self._search_matches)
        ):
            self._apply_current_highlights()
            self._update_search_counter()
            return

        start = self._search_matches[self._current_match_index]
        end = start + len(query)
        cursor = self.viewer.textCursor()
        cursor.setPosition(start)
        cursor.setPosition(end, QTextCursor.KeepAnchor)
        self.viewer.setTextCursor(cursor)
        self.viewer.centerCursor()

        self._apply_current_highlights(self._current_search_highlight_selections())
        self._update_search_counter()

    def _current_search_highlight_selections(self):
        query = (self.search_input.text() or "").strip()
        text = self.viewer.toPlainText() or ""
        if (
            not query
            or not text
            or not self._search_matches
            or self._current_match_index < 0
            or self._current_match_index >= len(self._search_matches)
        ):
            return []

        start = self._search_matches[self._current_match_index]
        end = start + len(query)
        cursor = QTextCursor(self.viewer.document())
        cursor.setPosition(start)
        cursor.setPosition(end, QTextCursor.KeepAnchor)

        current_selection = QTextEdit.ExtraSelection()
        current_selection.cursor = cursor
        current_fmt = QTextCharFormat()
        current_fmt.setBackground(QColor("#F4D35E"))
        current_fmt.setForeground(QColor("#111111"))
        current_selection.format = current_fmt

        selections = [current_selection]
        for pos in self._search_matches:
            if pos == start:
                continue
            secondary_cursor = QTextCursor(self.viewer.document())
            secondary_cursor.setPosition(pos)
            secondary_cursor.setPosition(pos + len(query), QTextCursor.KeepAnchor)
            secondary_selection = QTextEdit.ExtraSelection()
            secondary_selection.cursor = secondary_cursor
            secondary_fmt = QTextCharFormat()
            secondary_fmt.setBackground(QColor("#B58E00"))
            secondary_fmt.setForeground(QColor("#F5F5F5"))
            secondary_selection.format = secondary_fmt
            selections.append(secondary_selection)

        return selections

    def _apply_current_highlights(self, search_selections=None):
        selections = []
        jump_selection = self._jumped_line_selection()
        if jump_selection is not None:
            selections.append(jump_selection)
        if search_selections:
            selections.extend(search_selections)
        self.viewer.setExtraSelections(selections)

    def _jumped_line_selection(self):
        if self._jumped_line_number is None:
            return None

        block = self.viewer.document().findBlockByNumber(self._jumped_line_number - 1)
        if not block.isValid():
            return None

        selection = QTextEdit.ExtraSelection()
        selection.cursor = QTextCursor(block)
        fmt = QTextCharFormat()
        fmt.setBackground(QColor("#2F6F9F"))
        fmt.setForeground(QColor("#FFFFFF"))
        fmt.setProperty(QTextFormat.FullWidthSelection, True)
        selection.format = fmt
        return selection

    def _update_search_counter(self):
        total = len(self._search_matches)
        current = self._current_match_index + 1 if self._current_match_index >= 0 else 0
        self.search_counter.setText(f"{current} / {total}")

    def _goto_next_match(self):
        if not self._search_matches:
            self._update_search_counter()
            return
        self._current_match_index = (self._current_match_index + 1) % len(self._search_matches)
        self._apply_current_match()

    def _goto_prev_match(self):
        if not self._search_matches:
            self._update_search_counter()
            return
        self._current_match_index = (self._current_match_index - 1) % len(self._search_matches)
        self._apply_current_match()


class ResultsViewerDialog(UniversalViewerDialog):
    def __init__(self, payload=None, parent=None):
        super().__init__(
            title="Results Viewer",
            payload=payload,
            parent=parent,
            show_summary=True,
            save_dialog_title="Save Results",
            default_save_stem="results",
        )
