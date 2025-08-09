# ui/panels/scraper_tab.py
from PySide6.QtWidgets import QWidget, QTableWidgetItem
from PySide6.QtCore import Qt
from ui.panels.scraper_panel_ui import Ui_scraper_panel  # генерится из .ui

class ScraperTabController(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = Ui_scraper_panel()
        self.ui.setupUi(self)

        # Кнопки
        self.ui.btnStart.clicked.connect(self.on_start_clicked)
        self.ui.btnStop.clicked.connect(self.on_stop_clicked)
        self.ui.btnExport.clicked.connect(self.on_export_clicked)

        self._setup_table()
        self._log("[INIT] Scraper tab ready")

    def _setup_table(self):
        t = self.ui.taskTable
        t.setRowCount(0)
        t.setSortingEnabled(True)
        t.setAlternatingRowColors(True)
        t.setSelectionBehavior(t.SelectionBehavior.SelectRows)
        t.setSelectionMode(t.SelectionMode.SingleSelection)
        t.setEditTriggers(t.EditTrigger.NoEditTriggers)
        header = t.horizontalHeader()
        header.setStretchLastSection(True)
        # header.setSectionResizeMode(0, header.ResizeMode.Stretch)  # если нужно растянуть обе

    def on_start_clicked(self):
        self._log("[INFO] Start clicked")
        # TODO: core.scraper.task_manager.start()

    def on_stop_clicked(self):
        self._log("[INFO] Stop clicked")
        # TODO: core.scraper.task_manager.stop()

    def on_export_clicked(self):
        self._log("[INFO] Export clicked")
        # TODO: exporter CSV/XLSX

    # === helpers ===
    def _log(self, text: str):
        self.ui.logOutput.appendPlainText(text)

    def add_task_row(self, url: str, status: str = "Pending"):
        r = self.ui.taskTable.rowCount()
        self.ui.taskTable.insertRow(r)
        self.ui.taskTable.setItem(r, 0, QTableWidgetItem(url))
        self.ui.taskTable.setItem(r, 1, QTableWidgetItem(status))
