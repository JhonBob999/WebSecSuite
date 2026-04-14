from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)


class ResultsViewerDialog(QDialog):
    def __init__(self, payload=None, parent=None):
        super().__init__(parent)
        self._payload = payload
        self._pretty_mode = True

        self.setWindowTitle("Results Viewer")
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

        self._refresh_text()

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

    def _show_pretty_json(self):
        self._pretty_mode = True
        self._refresh_text()

    def _show_raw_json(self):
        self._pretty_mode = False
        self._refresh_text()

    def _copy_current_text(self):
        QGuiApplication.clipboard().setText(self.viewer.toPlainText() or "")

    def _save_to_file(self):
        default_name = "results.json" if self._pretty_mode else "results.txt"
        default_path = str(Path("data") / "exports" / default_name)
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Results",
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
