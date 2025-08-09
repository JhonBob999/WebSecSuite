from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QCoreApplication
import sys
from mainwindow import MainWindow

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()

    def _graceful_shutdown():
        try:
            scraper_tab = getattr(window, "scraper_tab", None) or \
                        getattr(getattr(window, "ui", object()), "scraper_tab", None) or \
                        getattr(window, "get_scraper_tab", lambda: None)()
            if scraper_tab and hasattr(scraper_tab, "task_manager"):
                summary = scraper_tab.task_manager.shutdown(timeout_ms=5000)
                # (опционально) быстрый лог в консоль:
                print(f"[SCRAPER] shutdown: stopped={summary['stopped']} "
                    f"joined={summary['joined']} left={len(summary['left'])}")
        except Exception:
            pass

    QCoreApplication.instance().aboutToQuit.connect(_graceful_shutdown)
    sys.exit(app.exec())
