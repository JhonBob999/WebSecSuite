from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QColor, QFont, QGuiApplication, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class UniversalViewerDialog(QDialog):
    def __init__(
        self,
        payload=None,
        parent=None,
        *,
        title: str = "Universal Viewer",
        save_dialog_title: str = "Save Viewer Content",
        pretty_default_name: str = "viewer.json",
        raw_default_name: str = "viewer.txt",
    ):
        super().__init__(parent)
        self._payload = payload
        self._pretty_mode = True
        self._search_matches: list[int] = []
        self._current_match_index = -1
        self._save_dialog_title = save_dialog_title
        self._pretty_default_name = pretty_default_name
        self._raw_default_name = raw_default_name
        self._empty_value = "\u2014"

        self.setWindowTitle(title)
        self.resize(980, 640)

        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

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
        self.btn_prev = QPushButton("Prev", self)
        self.btn_next = QPushButton("Next", self)
        self.search_counter = QLabel("0 / 0", self)
        search_row.addWidget(self.search_label)
        search_row.addWidget(self.search_input, 1)
        search_row.addWidget(self.btn_prev)
        search_row.addWidget(self.btn_next)
        search_row.addWidget(self.search_counter)
        root.addLayout(search_row)

        self.viewer = QPlainTextEdit(self)
        self.viewer.setReadOnly(True)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.Monospace)
        self.viewer.setFont(mono)
        root.addWidget(self.viewer, 1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        self.btn_copy = QPushButton("Copy", self)
        self.btn_pretty = QPushButton("Pretty JSON", self)
        self.btn_raw = QPushButton("Raw JSON", self)
        self.btn_save = QPushButton("Save to file", self)
        self.btn_close = QPushButton("Close", self)
        btn_row.addWidget(self.btn_copy)
        btn_row.addWidget(self.btn_pretty)
        btn_row.addWidget(self.btn_raw)
        btn_row.addWidget(self.btn_save)
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
            empty = self._empty_value
            return f"URL: {empty}\nfinal_url: {empty}\nstatus_code: {empty}\ntime/request_ms: {empty}"

        empty = self._empty_value
        url = payload.get("url") or empty
        final_url = payload.get("final_url") or empty
        status = payload.get("status_code")
        timings = payload.get("timings") if isinstance(payload.get("timings"), dict) else {}
        request_ms = timings.get("request_ms")
        t_val = payload.get("time")
        time_val = request_ms if request_ms is not None else t_val
        return (
            f"URL: {url}\n"
            f"final_url: {final_url}\n"
            f"status_code: {status if status is not None else empty}\n"
            f"time/request_ms: {time_val if time_val is not None else empty}"
        )

    def _json_text(self, pretty: bool) -> str:
        data = self._payload
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
        self.viewer.setPlainText(self._json_text(pretty=self._pretty_mode))
        self._rebuild_search_index()

    def _show_pretty_json(self):
        self._pretty_mode = True
        self._refresh_text()

    def _show_raw_json(self):
        self._pretty_mode = False
        self._refresh_text()

    def _copy_current_text(self):
        QGuiApplication.clipboard().setText(self.viewer.toPlainText() or "")

    def _save_to_file(self):
        default_name = self._pretty_default_name if self._pretty_mode else self._raw_default_name
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

    def _rebuild_search_index(self):
        query = (self.search_input.text() or "").strip()
        text = self.viewer.toPlainText() or ""
        self._search_matches = []
        self._current_match_index = -1
        self.viewer.setExtraSelections([])

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
            self.viewer.setExtraSelections([])
            self._update_search_counter()
            return

        start = self._search_matches[self._current_match_index]
        end = start + len(query)
        cursor = self.viewer.textCursor()
        cursor.setPosition(start)
        cursor.setPosition(end, QTextCursor.KeepAnchor)
        self.viewer.setTextCursor(cursor)
        self.viewer.centerCursor()

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
            secondary_cursor = self.viewer.textCursor()
            secondary_cursor.setPosition(pos)
            secondary_cursor.setPosition(pos + len(query), QTextCursor.KeepAnchor)
            secondary_selection = QTextEdit.ExtraSelection()
            secondary_selection.cursor = secondary_cursor
            secondary_fmt = QTextCharFormat()
            secondary_fmt.setBackground(QColor("#B58E00"))
            secondary_fmt.setForeground(QColor("#F5F5F5"))
            secondary_selection.format = secondary_fmt
            selections.append(secondary_selection)

        self.viewer.setExtraSelections(selections)
        self._update_search_counter()

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
