from PySide6.QtWidgets import QWidget
from ui.panels.scraper_panel_ui import Ui_scraper_panel

class ScraperTabController(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = Ui_scraper_panel()
        self.ui.setupUi(self)

        # Подключения кнопок, таблицы и логики здесь
