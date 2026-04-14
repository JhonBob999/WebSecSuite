from PySide6.QtWidgets import QMainWindow, QVBoxLayout
from ui.main.ui_form import Ui_MainWindow

# Подключаем ScraperTabController
from ui.panels.scraper_tab import ScraperTabController

class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle("WebSecSuite")

        # Делаем центральный layout адаптивным вместо фиксированной геометрии.
        root_layout = QVBoxLayout(self.ui.centralwidget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        root_layout.addWidget(self.ui.tabWidget)

        # Добавляем вкладку Scraper
        self.scraper_tab = ScraperTabController()
        self.ui.tabWidget.addTab(self.scraper_tab, "Scraper")
