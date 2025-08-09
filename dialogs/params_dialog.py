# dialogs/params_dialog.py
from __future__ import annotations

# === SECTION === Imports & Typing
from typing import Any, Dict
import json, re

from PySide6.QtWidgets import (
    QDialog, QFormLayout, QLineEdit, QComboBox, QSpinBox, QCheckBox,
    QDialogButtonBox, QVBoxLayout, QLabel, QWidget, QTextEdit
)

# === SECTION === Constants & Validators
DEFAULT_UA = "WebSecSuite/1.0 (+https://github.com/JhonBob999/WebSecSuite)"
# http/https/socks5/socks5h, с опциональными кредами
PROXY_RE = re.compile(r"^(https?|socks5h?|socks5)://(?:[^@\s/]+@)?[^:\s/]+:\d{2,5}$", re.IGNORECASE)


# === SECTION === Dialog
class ParamsDialog(QDialog):
    """
    Редактор параметров запроса.
    Таймаут — в секундах (для единообразия с остальной частью проекта).
    Headers можно вводить:
      • JSON-объектом: {"Accept": "text/html", "DNT": "1"}
      • По строкам:     Key: Value   (по одной паре на строку)
      • В одну строку:  k: v | k2: v2
    """
    def __init__(self, parent: QWidget | None = None, initial: Dict[str, Any] | None = None):
        super().__init__(parent)
        self.setWindowTitle("Edit Params")
        self.setModal(True)
        initial = dict(initial or {})

        # --- Method
        self.method = QComboBox()
        self.method.addItems(["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
        init_method = str(initial.get("method", "")).upper()
        if init_method and init_method in [self.method.itemText(i) for i in range(self.method.count())]:
            self.method.setCurrentText(init_method)

        # --- Proxy / User-Agent
        self.proxy = QLineEdit(str(initial.get("proxy", "") or ""))
        self.user_agent = QLineEdit(str(initial.get("user_agent", "") or ""))

        # --- Timeout (seconds)
        self.timeout = QSpinBox()
        self.timeout.setRange(1, 600)  # 1..600 секунд
        self.timeout.setSuffix(" s")
        self.timeout.setValue(int(initial.get("timeout", 20)))  # дефолт: 20s

        # --- Retries
        self.retries = QSpinBox()
        self.retries.setRange(0, 10)
        self.retries.setValue(int(initial.get("retries", 1)))

        # --- Headers (QTextEdit для удобства)
        self.headers = QTextEdit()
        hdr = initial.get("headers", {})
        if isinstance(hdr, dict):
            # Отобразим как k: v | k2: v2 (компактно), но парсер понимает и JSON, и построчно
            compact = " | ".join(f"{k}: {v}" for k, v in hdr.items())
            self.headers.setPlainText(compact)
        else:
            self.headers.setPlainText(str(hdr or ""))

        # --- Save as default
        self.save_as_default = QCheckBox("Save as default for new tasks")
        self.save_as_default.setChecked(bool(initial.get("save_as_default", False)))

        # === SECTION === Layout
        form = QFormLayout()
        form.addRow("Method:", self.method)
        form.addRow("Proxy:", self.proxy)
        form.addRow("User-Agent:", self.user_agent)
        form.addRow("Timeout:", self.timeout)
        form.addRow("Retries:", self.retries)
        form.addRow(QLabel("Headers (JSON или 'Key: Value' построчно / через |):"))
        form.addRow(self.headers)
        form.addRow(self.save_as_default)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        root = QVBoxLayout(self)
        root.addLayout(form)
        root.addWidget(buttons)

        self._data: Dict[str, Any] = {}

    # === SECTION === Public API
    @property
    def data(self) -> Dict[str, Any]:
        """Итоговый словарь параметров после accept()."""
        return self._data

    # === SECTION === Helpers (headers/proxy parsing)
    def _parse_headers(self, text: str) -> Dict[str, str]:
        """
        Порядок попыток:
          1) JSON-объект
          2) Построчно: 'Key: Value'
          3) В одну строку через '|': 'k: v | k2: v2'
        """
        text = (text or "").strip()
        if not text:
            return {}

        # 1) JSON
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                # всё в str
                return {str(k): "" if v is None else str(v) for k, v in obj.items()}
        except Exception:
            pass

        # 2) Построчно
        if "\n" in text:
            hdrs: Dict[str, str] = {}
            for raw in text.splitlines():
                line = raw.strip()
                if not line:
                    continue
                if ":" not in line:
                    # допустим строка без двоеточия — считаем пустым значением
                    hdrs[line] = ""
                    continue
                k, v = line.split(":", 1)
                hdrs[k.strip()] = v.strip()
            return hdrs

        # 3) Через "|"
        hdrs: Dict[str, str] = {}
        for chunk in text.split("|"):
            p = chunk.strip()
            if not p:
                continue
            if ":" in p:
                k, v = p.split(":", 1)
                hdrs[k.strip()] = v.strip()
            else:
                hdrs[p] = ""
        return hdrs

    def _normalize_proxy(self, proxy: str | None) -> str | None:
        proxy = (proxy or "").strip()
        if not proxy:
            return None
        if PROXY_RE.match(proxy):
            return proxy
        # Не валидный — оставляем как None (или можно всплывашку делать выше по стеку)
        return None

    # === SECTION === Accept
    def accept(self) -> None:
        hdr_dict = self._parse_headers(self.headers.toPlainText())

        # Пустой UA → DEFAULT_UA (не оставляем пустым)
        ua = self.user_agent.text().strip() or DEFAULT_UA

        self._data = {
            "method": self.method.currentText(),
            "proxy": self._normalize_proxy(self.proxy.text()),
            "user_agent": ua,
            "timeout": int(self.timeout.value()),  # секунды
            "retries": int(self.retries.value()),
            "headers": hdr_dict,
            "save_as_default": self.save_as_default.isChecked(),
        }
        super().accept()
