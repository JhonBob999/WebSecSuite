from __future__ import annotations

import json
from typing import Any, List

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QPlainTextEdit,
)
from PySide6.QtWidgets import QAbstractItemView, QHeaderView


def _shorten(text: Any, limit: int = 120) -> str:
    val = "" if text is None else str(text)
    if len(val) <= limit:
        return val
    return val[: limit - 1] + "…"


class FormsViewerDialog(QDialog):
    def __init__(self, parent=None, forms: List[dict] | None = None, target_url: str | None = None):
        super().__init__(parent)
        self.forms: List[dict] = forms or []
        self.target_url = target_url or ""

        self.setWindowTitle("Forms Viewer")
        self.setMinimumSize(1000, 650)

        main_layout = QVBoxLayout(self)

        # Counters
        self.counters_label = QLabel(self)
        main_layout.addWidget(self.counters_label)

        # Splitter
        splitter = QSplitter(Qt.Horizontal, self)
        main_layout.addWidget(splitter, stretch=1)

        left_panel = QWidget(splitter)
        left_layout = QVBoxLayout(left_panel)
        self.table_forms = QTableWidget(left_panel)
        left_layout.addWidget(self.table_forms)

        right_panel = QWidget(splitter)
        right_layout = QVBoxLayout(right_panel)
        self.table_inputs = QTableWidget(right_panel)
        right_layout.addWidget(self.table_inputs, stretch=2)

        self.details_text = QPlainTextEdit(right_panel)
        self.details_text.setReadOnly(True)
        right_layout.addWidget(self.details_text, stretch=3)

        btn_bar = QHBoxLayout()
        self.btn_copy_template = QPushButton("Copy Template as JSON", right_panel)
        btn_bar.addWidget(self.btn_copy_template)
        btn_bar.addStretch(1)
        right_layout.addLayout(btn_bar)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)

        buttons = QDialogButtonBox(QDialogButtonBox.Close, parent=self)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        main_layout.addWidget(buttons)

        self._setup_tables()
        self._populate_forms()
        self._update_counters()
        self._update_details(None)

        self.table_forms.itemSelectionChanged.connect(self._on_form_selected)
        self.btn_copy_template.clicked.connect(self._on_copy_template)

    def _setup_tables(self):
        # Forms table
        self.table_forms.setColumnCount(4)
        self.table_forms.setHorizontalHeaderLabels(["Method", "Action", "Inputs", "Has file"])
        self.table_forms.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_forms.setEditTriggers(QAbstractItemView.NoEditTriggers)
        header = self.table_forms.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_forms.setAlternatingRowColors(True)
        self.table_forms.setSortingEnabled(False)

        # Inputs table
        self.table_inputs.setColumnCount(6)
        self.table_inputs.setHorizontalHeaderLabels(["Tag", "Type", "Name", "Value", "Required", "Checked"])
        self.table_inputs.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_inputs.setEditTriggers(QAbstractItemView.NoEditTriggers)
        header_inp = self.table_inputs.horizontalHeader()
        header_inp.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header_inp.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header_inp.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header_inp.setSectionResizeMode(3, QHeaderView.Stretch)
        header_inp.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header_inp.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table_inputs.setAlternatingRowColors(True)
        self.table_inputs.setSortingEnabled(False)

    def _populate_forms(self):
        table = self.table_forms
        table.setSortingEnabled(False)
        table.setRowCount(0)
        for form in self.forms:
            row = table.rowCount()
            table.insertRow(row)
            method = (form.get("method") or "").upper()
            action_full = form.get("action", "")
            action = _shorten(action_full)
            inputs_count = form.get("inputs_count") or len(form.get("inputs", []) or [])
            has_file = bool(form.get("has_file"))
            item_method = QTableWidgetItem(method)
            item_action = QTableWidgetItem(action)
            if action != action_full:
                item_action.setToolTip(str(action_full))
            table.setItem(row, 0, item_method)
            table.setItem(row, 1, item_action)
            table.setItem(row, 2, QTableWidgetItem(str(inputs_count)))
            table.setItem(row, 3, QTableWidgetItem("Yes" if has_file else "No"))
        table.setSortingEnabled(True)
        if table.rowCount():
            table.selectRow(0)

    def _populate_inputs(self, form: dict | None):
        table = self.table_inputs
        table.setSortingEnabled(False)
        table.setRowCount(0)
        if not form:
            table.setSortingEnabled(True)
            return
        for inp in form.get("inputs", []) or []:
            row = table.rowCount()
            table.insertRow(row)
            tag = inp.get("tag", "")
            itype = inp.get("type", "")
            name_full = inp.get("name", "")
            value_full = inp.get("value", "")
            name = _shorten(name_full)
            value = _shorten(value_full)
            required = "Yes" if inp.get("required") else "No"
            checked = "Yes" if inp.get("checked") else "No"
            item_tag = QTableWidgetItem(str(tag))
            item_type = QTableWidgetItem(str(itype))
            item_name = QTableWidgetItem(str(name))
            item_value = QTableWidgetItem(str(value))
            if name != name_full:
                item_name.setToolTip(str(name_full))
            if value != value_full:
                item_value.setToolTip(str(value_full))
            table.setItem(row, 0, item_tag)
            table.setItem(row, 1, item_type)
            table.setItem(row, 2, item_name)
            table.setItem(row, 3, item_value)
            table.setItem(row, 4, QTableWidgetItem(required))
            table.setItem(row, 5, QTableWidgetItem(checked))
        for col in range(0, 6):
            header = table.horizontalHeader()
            mode = header.sectionResizeMode(col)
            header.setSectionResizeMode(col, mode)
        table.setSortingEnabled(True)

    def _update_counters(self):
        forms_n = len(self.forms)
        inputs_n = sum(form.get("inputs_count") or len(form.get("inputs", []) or []) for form in self.forms)
        with_file = sum(1 for form in self.forms if form.get("has_file"))
        self.counters_label.setText(f"Forms: {forms_n} | Inputs: {inputs_n} | With file: {with_file}")

    def _update_details(self, form: dict | None):
        if not form:
            self.details_text.setPlainText("No forms")
            self._populate_inputs(None)
            return

        lines = [
            f"Method: {form.get('method', '')}",
            f"Action: {_shorten(form.get('action', ''))}",
            f"Enctype: {form.get('enctype', '')}",
        ]
        inputs = form.get("inputs", []) or []
        lines.append(f"Inputs ({len(inputs)}):")
        for inp in inputs:
            tag = inp.get("tag", "")
            itype = inp.get("type", "")
            name = _shorten(inp.get("name", ""))
            value = _shorten(inp.get("value", ""))
            req = " [required]" if inp.get("required") else ""
            lines.append(f"- {tag}/{itype} {name} = {value}{req}")

        self.details_text.setPlainText("\n".join(lines))
        self._populate_inputs(form)

    def _on_form_selected(self):
        table = self.table_forms
        if table is None or not table.selectionModel():
            self._populate_inputs(None)
            self._update_details(None)
            return

        selected = table.selectionModel().selectedRows()
        if not selected:
            self._populate_inputs(None)
            self._update_details(None)
            return

        row = selected[0].row()
        if row < 0 or row >= len(self.forms):
            self._populate_inputs(None)
            self._update_details(None)
            return

        form = self.forms[row]

        # обновляем правую таблицу и details
        self._populate_inputs(form)
        self._update_details(form)



    def _on_copy_template(self):
        table = self.table_forms
        if table is None or not table.selectionModel():
            return
        selected = table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.information(self, "No template", "No form selected.")
            return
        row = selected[0].row()
        if row < 0 or row >= len(self.forms):
            QMessageBox.information(self, "No template", "No form selected.")
            return
        form = self.forms[row] or {}
        template = form.get("template")
        if not template:
            QMessageBox.information(self, "No template for this form", "No template for this form")
            return
        try:
            text = json.dumps(template, ensure_ascii=False, indent=2)
        except Exception:
            text = str(template)
        QGuiApplication.clipboard().setText(text)
        QMessageBox.information(self, "Template copied", "Template copied to clipboard.")
