# dialogs/params_dialog.py
from __future__ import annotations

from typing import Any, Dict
import json, re, os, sys
from pathlib import Path
from dialogs.params_dialog_cookies_tab import CookiesTab

from PySide6.QtWidgets import (
    QDialog, QFormLayout, QLineEdit, QComboBox, QSpinBox, QCheckBox,
    QDialogButtonBox, QVBoxLayout, QLabel, QWidget, QTextEdit, QTabWidget, QMessageBox, QPushButton
)
from PySide6.QtCore import Qt , Signal

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
# http/https/socks5/socks5h, с опциональными кредами
PROXY_RE = re.compile(r"^(https?|socks5h?|socks5)://(?:[^@\s/]+@)?[^:\s/]+:\d{2,5}$", re.IGNORECASE)

# --- helper для поиска файла рядом с проектом/билдом (PyInstaller совместимо)
def _resource_path(rel: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path.cwd()))
    p = base / rel
    if p.exists():
        return p
    # пробуем от корня проекта
    return Path.cwd() / rel


class ParamsDialog(QDialog):
    applied = Signal(dict)           # просто сохранить
    applied_and_run = Signal(dict)   # сохранить и сразу запустить
    def __init__(self, parent: QWidget | None = None, initial: Dict[str, Any] | None = None, task_url=""):
        super().__init__(parent)
        self.task_url = task_url or ""
        self.setWindowTitle("Edit Params")
        self.resize(1200, 720)
        self.setMinimumSize(1000, 600)
        self.setModal(True)
        initial = dict(initial or {})
        

        # ---------- Поля (модели) ----------
        # Method
        self.method = QComboBox()
        self.method.addItems(["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
        init_method = str(initial.get("method", "")).upper()
        if init_method and init_method in [self.method.itemText(i) for i in range(self.method.count())]:
            self.method.setCurrentText(init_method)

        # Proxy / User-Agent
        self.proxy = QLineEdit(str(initial.get("proxy", "") or ""))
        self.user_agent = QLineEdit(str(initial.get("user_agent", "") or ""))

        # --- НОВОЕ: пресеты UA
        self.ua_preset = QComboBox()
        self.ua_map: Dict[str, str] = self._load_ua_presets()  # name -> UA
        self._fill_ua_preset_combo(self.ua_map)

        self.user_agent = QLineEdit(str(initial.get("user_agent", "") or ""))
        if not self.user_agent.text().strip():
            self.user_agent.setText(DEFAULT_UA)

        self.timeout = QSpinBox(); self.timeout.setRange(1, 600); self.timeout.setSuffix(" s")
        self.timeout.setValue(int(initial.get("timeout", 20)))

        self.retries = QSpinBox(); self.retries.setRange(0, 10)
        self.retries.setValue(int(initial.get("retries", 1)))

        self.headers = QTextEdit()
        hdr = initial.get("headers", {})
        if isinstance(hdr, dict):
            compact = " | ".join(f"{k}: {v}" for k, v in hdr.items())
            self.headers.setPlainText(compact)
        else:
            self.headers.setPlainText(str(hdr or ""))

        self.save_as_default = QCheckBox("Save as default for new tasks")
        self.save_as_default.setChecked(bool(initial.get("save_as_default", False)))

        # ---------- Вкладки ----------
        self.tabs = QTabWidget()

        # Basic
        w_basic = QWidget(self)
        f_basic = QFormLayout(w_basic)
        f_basic.addRow("Method:", self.method)
        f_basic.addRow("UA preset:", self.ua_preset)  
        f_basic.addRow("User-Agent:", self.user_agent)
        f_basic.addRow("Timeout:", self.timeout)
        f_basic.addRow("Retries:", self.retries)
        self.tabs.addTab(w_basic, "Basic")

        # Headers
        w_headers = QWidget(self)
        v_headers = QVBoxLayout(w_headers)
        v_headers.addWidget(QLabel("Headers (JSON или 'Key: Value' построчно / через |):"))
        v_headers.addWidget(self.headers)
        self.tabs.addTab(w_headers, "Headers")

        # Advanced
        w_adv = QWidget(self)
        f_adv = QFormLayout(w_adv)
        f_adv.addRow("Proxy:", self.proxy)
        f_adv.addRow(self.save_as_default)
        self.tabs.addTab(w_adv, "Advanced")

        # ---------- Кнопки ----------
        self.buttons = QDialogButtonBox(QDialogButtonBox.Cancel)
        self.btn_apply = QPushButton("Apply")
        self.btn_apply_run = QPushButton("Apply && Run")
        self.buttons.addButton(self.btn_apply, QDialogButtonBox.AcceptRole)
        self.buttons.addButton(self.btn_apply_run, QDialogButtonBox.AcceptRole)
        self.buttons.rejected.connect(self.reject)
        self.btn_apply.clicked.connect(self.on_apply_clicked)
        self.btn_apply_run.clicked.connect(self.on_apply_run_clicked)

        # ---------- Корневой layout ----------
        root = QVBoxLayout(self)
        root.addWidget(self.tabs)
        root.addWidget(self.buttons)
        # --- связи пресетов ---
        self.ua_preset.currentTextChanged.connect(self._on_ua_preset_changed)
        # если initial содержит user_agent, попробуем выбрать соответствующий пресет
        self._select_preset_for_initial(self.user_agent.text())
        
        # Очистка подсветки ошибок по вводу
        self.proxy.textChanged.connect(lambda _: self._mark_invalid(self.proxy, False))
        self.user_agent.textChanged.connect(lambda _: self._mark_invalid(self.user_agent, False))
        self.headers.textChanged.connect(lambda: self._mark_invalid(self.headers, False))
        
        #Подключение Cookie окна
        self.tab_cookies = CookiesTab(self, initial_params=initial, task_url=self.task_url)
        self.tabs.addTab(self.tab_cookies, "Cookies")

        self._data: Dict[str, Any] = {}

    # === Public API ===
    @property
    def data(self) -> Dict[str, Any]:
        """Итоговый словарь параметров после accept()."""
        return self._data
    
    # ---------- UA presets ----------
    def _load_ua_presets(self) -> Dict[str, str]:
        """
        Возвращает плоский словарь {display_name: ua_string}.
        Поддерживает 2 формата JSON: «плоский» и «сгруппированный».
        """
        path = _resource_path("assets/presets/user_agents.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception:
            # fallback — минимальный набор
            return {
                "Desktop (Chrome)": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Desktop (Firefox)": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
                "Mobile (Android)": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
                "Mobile (iOS)": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
                "Tor (Generic)": "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
            }

        # плоский словарь?
        if isinstance(raw, dict) and all(isinstance(v, str) for v in raw.values()):
            return raw

        # сгруппированный словарь?
        flat: Dict[str, str] = {}
        if isinstance(raw, dict):
            for group, data in raw.items():
                if isinstance(data, dict):
                    for name, ua in data.items():
                        if isinstance(ua, str):
                            flat[f"{group} ({name})"] = ua
        return flat
    
    def _fill_ua_preset_combo(self, ua_map: Dict[str, str]) -> None:
        self.ua_preset.clear()
        self.ua_preset.addItem("Custom")  # режим ручного ввода
        for name in sorted(ua_map.keys()):
            self.ua_preset.addItem(name)

    def _on_ua_preset_changed(self, name: str) -> None:
        if name == "Custom":
            self.user_agent.setReadOnly(False)
            self.user_agent.setCursorPosition(len(self.user_agent.text()))
            return
        ua = self.ua_map.get(name, "")
        self.user_agent.setText(ua or DEFAULT_UA)
        self.user_agent.setReadOnly(True)

    def _select_preset_for_initial(self, current_ua: str) -> None:
        """
        Если initial.user_agent совпадает с одним из пресетов — выбрать его.
        Иначе — оставить Custom.
        """
        current = (current_ua or "").strip()
        for i in range(1, self.ua_preset.count()):  # пропускаем Custom (index 0)
            name = self.ua_preset.itemText(i)
            if self.ua_map.get(name, "").strip() == current:
                self.ua_preset.setCurrentIndex(i)
                self.user_agent.setReadOnly(True)
                return
        self.ua_preset.setCurrentIndex(0)  # Custom
        self.user_agent.setReadOnly(False)

    # ---------- ВАЛИДАЦИЯ И СБОР ДАННЫХ ----------
    def _parse_headers(self, text: str) -> Dict[str, str]:
        """Возвращает dict заголовков или выбрасывает ValueError с описанием ошибки."""
        text = (text or "").strip()
        if not text:
            return {}

        # Если пользователь явно пытался ввести JSON (есть фигурные скобки) — требуем корректный JSON
        if "{" in text or "}" in text:
            try:
                obj = json.loads(text)
            except Exception as e:
                raise ValueError(f"Headers JSON parse error: {e}")
            if not isinstance(obj, dict):
                raise ValueError("Headers JSON must be an object {key: value}.")
            return {str(k): "" if v is None else str(v) for k, v in obj.items()}

        # Построчно
        if "\n" in text:
            hdrs: Dict[str, str] = {}
            for idx, raw in enumerate(text.splitlines(), start=1):
                line = raw.strip()
                if not line:
                    continue
                if ":" not in line:
                    raise ValueError(f"Headers line {idx}: missing ':'")
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                if not k:
                    raise ValueError(f"Headers line {idx}: empty key")
                hdrs[k] = v
            return hdrs

        # В одну строку через |
        hdrs: Dict[str, str] = {}
        parts = [chunk.strip() for chunk in text.split("|") if chunk.strip()]
        for idx, p in enumerate(parts, start=1):
            if ":" not in p:
                raise ValueError(f"Headers part {idx}: expected 'Key: Value'")
            k, v = p.split(":", 1)
            k, v = k.strip(), v.strip()
            if not k:
                raise ValueError(f"Headers part {idx}: empty key")
            hdrs[k] = v
        return hdrs

    def _normalize_proxy(self, proxy: str | None) -> str | None:
        proxy = (proxy or "").strip()
        if not proxy:
            return None
        if PROXY_RE.match(proxy):
            return proxy
        # невалидный → None (валидацию с подсказкой добавим на следующем шаге)
        return None
    
    def _collect_params(self) -> Dict[str, Any]:
        """Собирает и валидирует поля. Выбрасывает ValueError при ошибке."""
        params: Dict[str, Any] = {
            "method": self.method.currentText(),
            "user_agent": (self.user_agent.text().strip() or DEFAULT_UA),
            "timeout": int(self.timeout.value()),
            "retries": int(self.retries.value()),
            "save_as_default": self.save_as_default.isChecked(),
        }

        # proxy
        try:
            params["proxy"] = self._normalize_proxy(self.proxy.text())
            self._mark_invalid(self.proxy, False)
        except ValueError:
            self._mark_invalid(self.proxy, True)
            raise

        # headers
        try:
            params["headers"] = self._parse_headers(self.headers.toPlainText())
            self._mark_invalid(self.headers, False)
        except ValueError:
            self._mark_invalid(self.headers, True)
            raise

        # COOKIES (если вкладка есть)
        if hasattr(self, "tab_cookies") and self.tab_cookies is not None:
            cookie_params = self.tab_cookies.collect_params()
            mode = cookie_params.get("cookie_mode", "auto")
            cookie_file = (cookie_params.get("cookie_file") or "").strip()

            # Валидация custom-режима
            if mode == "custom":
                # подсветим поле пути во вкладке Cookies, если оно пустое
                try:
                    # есть ли метод _mark_invalid у диалога — используем его для единого стиля
                    self._mark_invalid(self.tab_cookies.cookie_path_edit, not bool(cookie_file))
                except Exception:
                    pass
                if not cookie_file:
                    raise ValueError("Cookie mode = Custom: укажите путь к cookie-файлу.")

            # Сливаем в общий словарь
            params.update(cookie_params)

        return params
    
    # ---------- КНОПКИ ----------
    def on_apply_clicked(self) -> None:
        try:
            data = self._collect_params()
        except ValueError as e:
            QMessageBox.warning(self, "Validation error", str(e))
            return
        self._data = data
        self.applied.emit(data)
        self.accept()  # закрываем как обычный Apply (можно оставить open, если хочешь)

    def on_apply_run_clicked(self) -> None:
        try:
            data = self._collect_params()
        except ValueError as e:
            QMessageBox.warning(self, "Validation error", str(e))
            return
        self._data = data
        self.applied_and_run.emit(data)
        self.accept()

    # ---------- УТИЛИТЫ ----------
    def _mark_invalid(self, widget: QWidget, invalid: bool) -> None:
        if invalid:
            widget.setStyleSheet("border: 1px solid #d9534f;")  # красная рамка
        else:
            widget.setStyleSheet("")

    # === Accept ===
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
