import logging
import sys

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QCoreApplication

from core.paths import project_root
from mainwindow import MainWindow

logging.basicConfig(
    filename=str(project_root() / "error.log"),
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.showMaximized()

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
            logger.warning("Graceful shutdown failed", exc_info=True)

    QCoreApplication.instance().aboutToQuit.connect(_graceful_shutdown)
    sys.exit(app.exec())
