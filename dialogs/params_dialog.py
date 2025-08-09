from __future__ import annotations
from typing import Any, Dict
from PySide6.QtWidgets import (
    QDialog, QFormLayout, QLineEdit, QComboBox, QSpinBox, QCheckBox,
    QDialogButtonBox, QVBoxLayout, QLabel, QWidget
)

class ParamsDialog(QDialog):
    def __init__(self, parent: QWidget | None = None, initial: Dict[str, Any] | None = None):
        super().__init__(parent)
        self.setWindowTitle("Edit Params")
        self.setModal(True)
        initial = initial or {}

        self.method = QComboBox()
        self.method.addItems(["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"])
        if str(initial.get("method", "")).upper() in [self.method.itemText(i) for i in range(self.method.count())]:
            self.method.setCurrentText(str(initial.get("method", "")).upper())

        self.proxy = QLineEdit(str(initial.get("proxy", "") or ""))
        self.user_agent = QLineEdit(str(initial.get("user_agent", "") or ""))

        self.timeout = QSpinBox()
        self.timeout.setRange(1, 120000)  # мс
        self.timeout.setValue(int(initial.get("timeout", 5000)))

        self.retries = QSpinBox()
        self.retries.setRange(0, 10)
        self.retries.setValue(int(initial.get("retries", 0)))

        self.headers = QLineEdit()
        hdr = initial.get("headers", {})
        if isinstance(hdr, dict):
            self.headers.setText(" | ".join(f"{k}: {v}" for k, v in hdr.items()))
        else:
            self.headers.setText(str(hdr or ""))

        self.save_as_default = QCheckBox("Save as default for new tasks")

        form = QFormLayout()
        form.addRow("Method:", self.method)
        form.addRow("Proxy:", self.proxy)
        form.addRow("User-Agent:", self.user_agent)
        form.addRow("Timeout (ms):", self.timeout)
        form.addRow("Retries:", self.retries)
        form.addRow(QLabel("Headers (k: v | k2: v2):"))
        form.addRow(self.headers)
        form.addRow(self.save_as_default)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        root = QVBoxLayout(self)
        root.addLayout(form)
        root.addWidget(buttons)
        self._data: Dict[str, Any] = {}

    @property
    def data(self) -> Dict[str, Any]:
        return self._data

    def accept(self) -> None:
        hdr_text = self.headers.text().strip()
        hdr_dict: Dict[str, str] = {}
        if hdr_text:
            for chunk in hdr_text.split("|"):
                p = chunk.strip()
                if not p: 
                    continue
                if ":" in p:
                    k, v = p.split(":", 1)
                    hdr_dict[k.strip()] = v.strip()
                else:
                    hdr_dict[p] = ""
        self._data = {
            "method": self.method.currentText(),
            "proxy": self.proxy.text().strip() or None,
            "user_agent": self.user_agent.text().strip() or None,
            "timeout": int(self.timeout.value()),
            "retries": int(self.retries.value()),
            "headers": hdr_dict,
            "save_as_default": self.save_as_default.isChecked(),
        }
        super().accept()
