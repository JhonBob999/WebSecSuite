from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QGroupBox, QHBoxLayout, QRadioButton, QButtonGroup,
    QLineEdit, QPushButton, QLabel, QCheckBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QFileDialog, QMessageBox, QAbstractItemView, QDialog, QFormLayout,
    QDialogButtonBox, QDateTimeEdit
)
from PySide6.QtCore import Qt, QDateTime
from pathlib import Path
import time
from http.cookiejar import Cookie, CookieJar

from core.cookies.storage import (
    load_cookiejar, save_cookiejar, derive_domain_from_url, file_for_domain
)

class CookieEditDialog(QDialog):
    """Простое окно для редактирования одного cookie."""
    def __init__(self, parent=None, name="", value="", domain="", path="/", expires=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Cookie")
        self.setModal(True)
        self.setMinimumWidth(480)

        self.name_edit = QLineEdit(name)
        self.value_edit = QLineEdit(value)
        self.domain_edit = QLineEdit(domain)
        self.path_edit = QLineEdit(path)

        self.expires_dt = QDateTimeEdit(self)
        self.expires_dt.setCalendarPopup(True)
        self.expires_dt.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.session_checkbox = QCheckBox("Session (no expires)")
        if expires:
            # expires — UNIX timestamp (int)
            self.session_checkbox.setChecked(False)
            self.expires_dt.setDateTime(QDateTime.fromSecsSinceEpoch(int(expires)))
        else:
            self.session_checkbox.setChecked(True)
            self.expires_dt.setDateTime(QDateTime.currentDateTime().addYears(1))
        self.expires_dt.setEnabled(not self.session_checkbox.isChecked())
        self.session_checkbox.toggled.connect(self.expires_dt.setDisabled)

        form = QFormLayout()
        form.addRow("Name", self.name_edit)
        form.addRow("Value", self.value_edit)
        form.addRow("Domain", self.domain_edit)
        form.addRow("Path", self.path_edit)
        row = QHBoxLayout()
        row.addWidget(self.session_checkbox)
        row.addWidget(self.expires_dt, 1)
        form.addRow("Expires", row)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        main = QVBoxLayout(self)
        main.addLayout(form)
        main.addWidget(btns)

    def data(self):
        name = self.name_edit.text().strip()
        value = self.value_edit.text().strip()
        domain = self.domain_edit.text().strip()
        path = self.path_edit.text().strip() or "/"
        expires = None if self.session_checkbox.isChecked() else int(self.expires_dt.dateTime().toSecsSinceEpoch())
        return {"name": name, "value": value, "domain": domain, "path": path, "expires": expires}



class CookiesTab(QWidget):
    """
    Вкладка Cookies для ParamsDialog.
    Работает с task.params:
      cookie_mode: auto|custom|none
      cookie_file: str (если custom)
      auto_save_cookies: bool
      clear_cookies_before_run: bool
    """
    def __init__(self, parent=None, initial_params=None, task_url=""):
        super().__init__(parent)
        self.params = dict(initial_params or {})
        self.task_url = task_url
        self._init_ui()
        self._load_initial()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # === Source group ===
        src_group = QGroupBox("Source")
        src_layout = QVBoxLayout(src_group)

        self.mode_group = QButtonGroup(self)
        self.rb_auto = QRadioButton("Auto by domain")
        self.rb_custom = QRadioButton("Custom file")
        self.rb_none = QRadioButton("No cookies")
        self.mode_group.addButton(self.rb_auto)
        self.mode_group.addButton(self.rb_custom)
        self.mode_group.addButton(self.rb_none)

        for rb in (self.rb_auto, self.rb_custom, self.rb_none):
            src_layout.addWidget(rb)

        file_layout = QHBoxLayout()
        self.cookie_path_edit = QLineEdit()
        self.cookie_path_edit.setPlaceholderText("Cookie file path")
        self.btn_browse = QPushButton("Browse…")
        self.btn_reload = QPushButton("Reload")
        file_layout.addWidget(self.cookie_path_edit, 1)
        file_layout.addWidget(self.btn_browse)
        file_layout.addWidget(self.btn_reload)
        src_layout.addLayout(file_layout)

        self.lbl_status = QLabel("Loaded: 0")
        src_layout.addWidget(self.lbl_status)

        layout.addWidget(src_group)

        # === Options ===
        opt_group = QGroupBox("Options")
        opt_layout = QVBoxLayout(opt_group)
        self.cb_auto_save = QCheckBox("Auto save after run")
        self.cb_clear_before = QCheckBox("Clear before run")
        opt_layout.addWidget(self.cb_auto_save)
        opt_layout.addWidget(self.cb_clear_before)
        layout.addWidget(opt_group)

        # Viewer + actions
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Name", "Value", "Domain", "Path", "Expires"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        layout.addWidget(self.table, 1)

        actions = QHBoxLayout()
        self.btn_add = QPushButton("Add")
        self.btn_edit = QPushButton("Edit")
        self.btn_delete = QPushButton("Delete")
        self.btn_save_now = QPushButton("Save now")
        actions.addWidget(self.btn_add)
        actions.addWidget(self.btn_edit)
        actions.addWidget(self.btn_delete)
        actions.addStretch(1)
        actions.addWidget(self.btn_save_now)
        layout.addLayout(actions)

        # Connections
        self.btn_browse.clicked.connect(self._choose_file)
        self.btn_reload.clicked.connect(self._reload_cookies)
        self.mode_group.buttonClicked.connect(self._mode_changed)

        self.btn_add.clicked.connect(self._on_add)
        self.btn_edit.clicked.connect(self._on_edit)
        self.btn_delete.clicked.connect(self._on_delete)
        self.btn_save_now.clicked.connect(self._on_save_now)

    def _load_initial(self):
        mode = self.params.get("cookie_mode", "auto")
        if mode == "custom":
            self.rb_custom.setChecked(True)
        elif mode == "none":
            self.rb_none.setChecked(True)
        else:
            self.rb_auto.setChecked(True)

        self.cb_auto_save.setChecked(self.params.get("auto_save_cookies", True))
        self.cb_clear_before.setChecked(self.params.get("clear_cookies_before_run", False))
        self.cookie_path_edit.setText(self.params.get("cookie_file", ""))

        self._reload_cookies()

    def _mode_changed(self):
        if self.rb_auto.isChecked():
            self.cookie_path_edit.setReadOnly(True)
            auto_path = str(file_for_domain(derive_domain_from_url(self.task_url)))
            self.cookie_path_edit.setText(auto_path)
        elif self.rb_custom.isChecked():
            self.cookie_path_edit.setReadOnly(False)
        elif self.rb_none.isChecked():
            self.cookie_path_edit.clear()
            self.cookie_path_edit.setReadOnly(True)
            self.table.setRowCount(0)
            self.lbl_status.setText("No cookies")
            # обновим текущий путь для Save now
        self._update_current_path()

    def _choose_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select cookie file", "", "JSON Files (*.json)")
        if path:
            self.cookie_path_edit.setText(path)
            self._reload_cookies()
            
    def _update_current_path(self):
        cookie_file = self.cookie_path_edit.text().strip()
        if self.rb_none.isChecked():
            self._current_path = None
        elif cookie_file:
            self._current_path = Path(cookie_file)
        else:
            self._current_path = None

    def _reload_cookies(self):
        if self.rb_none.isChecked():
            return
        cookie_file = self.cookie_path_edit.text().strip()
        if not cookie_file and self.rb_auto.isChecked():
            cookie_file = str(file_for_domain(derive_domain_from_url(self.task_url)))
            self.cookie_path_edit.setText(cookie_file)

        jar, path, loaded = load_cookiejar(url=self.task_url, cookie_file=cookie_file)
        self._populate_from_jar(jar)
        self.lbl_status.setText(f"Loaded: {loaded} from {path}")
        self._current_path = path
        
    # ---------- table helpers ----------
    def _populate_from_jar(self, jar: CookieJar):
        self.table.setRowCount(0)
        for c in jar:
            self._append_row(c.name, c.value, c.domain, c.path, c.expires)

    def _append_row(self, name, value, domain, path, expires):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(name))
        self.table.setItem(row, 1, QTableWidgetItem(value))
        self.table.setItem(row, 2, QTableWidgetItem(domain))
        self.table.setItem(row, 3, QTableWidgetItem(path or "/"))
        self.table.setItem(row, 4, QTableWidgetItem(str(expires) if expires else "Session"))

    def _row_to_cookie(self, row: int) -> Cookie:
        name = self.table.item(row, 0).text()
        value = self.table.item(row, 1).text()
        domain = self.table.item(row, 2).text()
        path = self.table.item(row, 3).text() or "/"
        expires_text = self.table.item(row, 4).text()
        expires = None if (not expires_text or expires_text.lower() == "session") else int(expires_text)

        # Минимально достаточное создание cookie
        return Cookie(
            version=0, name=name, value=value, port=None, port_specified=False,
            domain=domain, domain_specified=bool(domain), domain_initial_dot=domain.startswith("."),
            path=path, path_specified=True, secure=False, expires=expires, discard=False,
            comment=None, comment_url=None, rest={}, rfc2109=False
        )
        
    def _table_to_jar(self) -> CookieJar:
        jar = CookieJar()
        for row in range(self.table.rowCount()):
            jar.set_cookie(self._row_to_cookie(row))
        return jar
    
    # ---------- actions ----------
    def _on_add(self):
        # домен по умолчанию из URL
        def_domain = "." + (derive_domain_from_url(self.task_url) or "example.com")
        dlg = CookieEditDialog(self, name="", value="", domain=def_domain, path="/", expires=None)
        if dlg.exec() == QDialog.Accepted:
            d = dlg.data()
            if not d["name"]:
                QMessageBox.warning(self, "Validation", "Name is required.")
                return
            self._append_row(d["name"], d["value"], d["domain"], d["path"], d["expires"])

    def _on_edit(self):
        row = self.table.currentRow()
        if row < 0:
            return
        # preload
        name = self.table.item(row, 0).text()
        value = self.table.item(row, 1).text()
        domain = self.table.item(row, 2).text()
        path = self.table.item(row, 3).text()
        expires_text = self.table.item(row, 4).text()
        expires = None if expires_text.lower() == "session" else int(expires_text)

        dlg = CookieEditDialog(self, name=name, value=value, domain=domain, path=path, expires=expires)
        if dlg.exec() == QDialog.Accepted:
            d = dlg.data()
            if not d["name"]:
                QMessageBox.warning(self, "Validation", "Name is required.")
                return
            self.table.item(row, 0).setText(d["name"])
            self.table.item(row, 1).setText(d["value"])
            self.table.item(row, 2).setText(d["domain"])
            self.table.item(row, 3).setText(d["path"] or "/")
            self.table.item(row, 4).setText(str(d["expires"]) if d["expires"] else "Session")

    def _on_delete(self):
        row = self.table.currentRow()
        if row < 0:
            return
        self.table.removeRow(row)

    def _on_save_now(self):
        if self.rb_none.isChecked():
            QMessageBox.information(self, "Cookies", "Cookie mode is 'None'. Nothing to save.")
            return
        # путь
        self._update_current_path()
        if not self._current_path:
            QMessageBox.warning(self, "Cookies", "No cookie file path.")
            return
        jar = self._table_to_jar()
        saved = save_cookiejar(self._current_path, jar)
        self.lbl_status.setText(f"Saved: {saved} → {self._current_path}")
        QMessageBox.information(self, "Cookies", f"Saved {saved} cookies to:\n{self._current_path}")

    # ---------- export to params ----------
    def collect_params(self):
        mode = "auto" if self.rb_auto.isChecked() else "custom" if self.rb_custom.isChecked() else "none"
        return {
            "cookie_mode": mode,
            "cookie_file": self.cookie_path_edit.text().strip() if mode == "custom" else "",
            "auto_save_cookies": self.cb_auto_save.isChecked(),
            "clear_cookies_before_run": self.cb_clear_before.isChecked()
        }
