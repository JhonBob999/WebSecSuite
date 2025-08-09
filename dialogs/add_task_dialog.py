from pathlib import Path
import json, re
from PySide6 import QtCore, QtGui, QtWidgets
# проверь название класса внутри ui-файла (скорее всего Ui_Dialog)
from ui.dialogs.add_task_dialog_ui import Ui_Dialog  

DEFAULT_UA = "WebSecSuite/1.0 (+https://github.com/JhonBob999/WebSecSuite)"
PROXY_RE = re.compile(r"^(https?|socks5)://(?:[^@\s/]+@)?[^:\s/]+:\d{2,5}$", re.IGNORECASE)

class AddTaskDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.setWindowTitle("Add Task")
        self.data = None

        # валидаторы/плейсхолдеры
        self.ui.timeout_input.setValidator(QtGui.QIntValidator(1, 600, self))
        self.ui.timeout_input.setPlaceholderText("20 (seconds)")
        self.ui.user_agent_input.setPlaceholderText(DEFAULT_UA)
        self.ui.proxy_input.setPlaceholderText("http://user:pass@host:port  |  socks5://host:port")
        self.ui.header_textedit.setPlaceholderText('{"Accept": "text/html"}')

        # кнопки
        self.ui.btn_ok.clicked.connect(self._on_accept)
        self.ui.btn_cancel.clicked.connect(self.reject)
        # retries: границы
        self.ui.retries_spin.setRange(0, 5)   # 0 = без повторов
        self.ui.retries_spin.setValue(0)


    def _validate_url(self, url: str) -> bool:
        q = QtCore.QUrl(url)
        return q.isValid() and q.scheme() in ("http", "https") and bool(q.host())

    def _normalize_url(self, url: str) -> str:
        url = (url or "").strip()
        if not url:
            return url
        q = QtCore.QUrl.fromUserInput(url)   # понимает example.com, localhost:8000 и т.п.
        if not q.scheme():
            q.setScheme("https")             # дефолтная схема
        return q.toString()                  # без StrictMode

    def _parse_headers(self, txt: str):
        txt = (txt or "").strip()
        if not txt:
            return {}
        return json.loads(txt)

    def _validate_proxy(self, proxy: str) -> bool:
        proxy = (proxy or "").strip()
        if not proxy:
            return True
        return bool(PROXY_RE.match(proxy))

    def _on_accept(self):
        url = self._normalize_url(self.ui.url_input.text())
        method = (self.ui.http_combox.currentText() or "GET").upper()
        headers_txt = self.ui.header_textedit.toPlainText()
        proxy = self.ui.proxy_input.text().strip()
        ua = self.ui.user_agent_input.text().strip() or DEFAULT_UA
        timeout_str = self.ui.timeout_input.text().strip()
        retries = int(self.ui.retries_spin.value())

        if not self._validate_url(url):
            QtWidgets.QMessageBox.critical(self, "Invalid URL", "Введите корректный http/https URL.")
            self.ui.url_input.setFocus()
            return
        try:
            headers = self._parse_headers(headers_txt)
            if not isinstance(headers, dict):
                raise ValueError("Headers must be a JSON object (dict).")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Invalid headers JSON", f"{e}")
            self.ui.header_textedit.setFocus(); return

        if not self._validate_proxy(proxy):
            QtWidgets.QMessageBox.critical(self, "Invalid proxy", "Ожидается: scheme://[user:pass@]host:port (http/https/socks5).")
            self.ui.proxy_input.setFocus(); return

        try:
            timeout = int(timeout_str) if timeout_str else 20
            if timeout <= 0: raise ValueError
        except Exception:
            QtWidgets.QMessageBox.critical(self, "Invalid timeout", "Timeout должен быть положительным целым числом.")
            self.ui.timeout_input.setFocus(); return

        self.data = {
            "url": url,
            "method": method,
            "headers": headers,
            "user_agent": ua,
            "proxy": proxy or None,
            "timeout": timeout,
            "retries": retries,
        }
        self.accept()
