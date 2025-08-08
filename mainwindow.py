from PySide6.QtWidgets import QMainWindow
from ui.main.ui_form import Ui_MainWindow

# Подключаем ScraperTabController
from ui.panels.scraper_tab import ScraperTabController

class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Добавляем вкладку Scraper
        self.scraper_tab = ScraperTabController()
        self.ui.tabWidget.addTab(self.scraper_tab, "Scraper")
