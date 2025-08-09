# dialogs/add_task_dialog.py
from __future__ import annotations

# === SECTION === Imports & Constants
from pathlib import Path
import json, re
from typing import Dict, List, Tuple
from PySide6 import QtCore, QtGui, QtWidgets
from ui.dialogs.add_task_dialog_ui import Ui_Dialog  # проверь имя класса в ui-модуле

DEFAULT_UA = "WebSecSuite/1.0 (+https://github.com/JhonBob999/WebSecSuite)"
PROXY_RE = re.compile(r"^(https?|socks5h?|socks5)://(?:[^@\s/]+@)?[^:\s/]+:\d{2,5}$", re.IGNORECASE)


# === SECTION === Dialog
class AddTaskDialog(QtWidgets.QDialog):
    """
    Диалог добавления задач.
    Поддерживает:
      • один или несколько URL (по одному на строку);
      • заголовки в формате JSON или 'Key: Value' строками;
      • валидации proxy/timeout;
      • возврат данных как через self.data (совместимость), так и через get_payload().
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.setWindowTitle("Add Task")

        # будет заполнено при accept()
        self.data: Dict = {}
        self._urls: List[str] = []
        self._params: Dict = {}

        # === UI defaults / validators
        self.ui.timeout_input.setValidator(QtGui.QIntValidator(1, 600, self))
        self.ui.timeout_input.setPlaceholderText("20 (seconds)")
        self.ui.user_agent_input.setPlaceholderText(DEFAULT_UA)
        self.ui.proxy_input.setPlaceholderText("http://user:pass@host:port  |  socks5://host:port")
        self.ui.header_textedit.setPlaceholderText('{"Accept": "text/html"}')

        self.ui.retries_spin.setRange(0, 5)   # 0 = без повторов
        self.ui.retries_spin.setValue(1)

        # === Signals
        self.ui.btn_ok.clicked.connect(self._on_accept)
        self.ui.btn_cancel.clicked.connect(self.reject)

    # === SECTION === Validators & Parsers
    def _validate_url(self, url: str) -> bool:
        q = QtCore.QUrl(url)
        return q.isValid() and q.scheme() in ("http", "https") and bool(q.host())

    def _normalize_url(self, url: str) -> str:
        url = (url or "").strip()
        if not url:
            return url
        q = QtCore.QUrl.fromUserInput(url)   # понимает example.com и т.п.
        if not q.scheme():
            q.setScheme("https")
        return q.toString()

    def _parse_multiple_urls(self, raw: str) -> List[str]:
        lines = [self._normalize_url(x) for x in (raw or "").splitlines()]
        urls = [u for u in lines if u]
        # валидация всех
        bad = [u for u in urls if not self._validate_url(u)]
        if bad:
            raise ValueError(f"Некорректные URL:\n• " + "\n• ".join(bad))
        return urls

    def _parse_headers(self, txt: str) -> Dict[str, str]:
        """
        Сначала пытаемся JSON ({}). Если не вышло — поддерживаем построчный синтаксис:
            Key: Value
            Another-Key: Value2
        Пустые строки игнорим.
        """
        txt = (txt or "").strip()
        if not txt:
            return {}
        # JSON попытка
        try:
            obj = json.loads(txt)
            if not isinstance(obj, dict):
                raise ValueError("Headers must be an object.")
            # нормализуем ключи опционально, но не меняем регистр
            return {str(k): str(v) for k, v in obj.items()}
        except Exception:
            pass

        # Построчный Key: Value
        headers: Dict[str, str] = {}
        for i, line in enumerate(txt.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                raise ValueError(f"Строка {i}: ожидается 'Key: Value'.")
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip()
            if not k:
                raise ValueError(f"Строка {i}: пустой ключ.")
            headers[k] = v
        return headers

    def _validate_proxy(self, proxy: str) -> bool:
        proxy = (proxy or "").strip()
        if not proxy:
            return True
        return bool(PROXY_RE.match(proxy))

    # === SECTION === Accept handler
    def _on_accept(self):
        raw_urls = self.ui.url_input.text() if hasattr(self.ui, "url_input") else self.ui.url_input.text()
        method = (self.ui.http_combox.currentText() or "GET").upper()
        headers_txt = self.ui.header_textedit.toPlainText()
        proxy = (self.ui.proxy_input.text() or "").strip()
        ua = (self.ui.user_agent_input.text() or "").strip() or DEFAULT_UA
        timeout_str = (self.ui.timeout_input.text() or "").strip()
        retries = int(self.ui.retries_spin.value())

        # URLs
        try:
            self._urls = self._parse_multiple_urls(raw_urls)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Invalid URL(s)", str(e))
            return
        if not self._urls:
            QtWidgets.QMessageBox.critical(self, "Invalid URL", "Введите хотя бы один http/https URL.")
            return

        # Headers
        try:
            headers = self._parse_headers(headers_txt)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Invalid headers", str(e))
            self.ui.header_textedit.setFocus()
            return

        # Proxy
        if not self._validate_proxy(proxy):
            QtWidgets.QMessageBox.critical(
                self, "Invalid proxy",
                "Ожидается: scheme://[user:pass@]host:port (http/https/socks5/socks5h)."
            )
            self.ui.proxy_input.setFocus()
            return

        # Timeout
        try:
            timeout = int(timeout_str) if timeout_str else 20
            if timeout <= 0:
                raise ValueError
        except Exception:
            QtWidgets.QMessageBox.critical(self, "Invalid timeout", "Timeout должен быть положительным целым числом.")
            self.ui.timeout_input.setFocus()
            return

        # Собираем params (универсально для TaskManager.create_task(url, params))
        self._params = {
            "method": method,
            "headers": headers,
            "user_agent": ua,
            "proxy": proxy or None,
            "timeout": timeout,
            "retries": retries,
        }

        # Совместимость: self.data — как раньше (первый URL + плоские поля)
        self.data = {"url": self._urls[0], **self._params}

        self.accept()

    # === SECTION === Public API
    def get_payload(self) -> Tuple[List[str], Dict]:
        """
        Возвращает (urls, params) после успешного accept().
        urls — список (поддержка пакетного добавления).
        params — словарь параметров запроса.
        """
        return self._urls, self._params
