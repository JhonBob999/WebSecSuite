from itertools import combinations
import os
from pathlib import Path
import sys

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtTest import QTest


@pytest.fixture(scope="module", autouse=True)
def windows_offscreen_fonts(qapp):
    original_font = qapp.font()
    font_ids = []
    # The Windows offscreen plugin may start with no fonts and measure boxes
    # instead of text. Use installed system fonts for realistic geometry.
    if sys.platform == "win32" and not QFontDatabase.families():
        font_dir = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
        for filename in ("segoeui.ttf", "segoeuib.ttf"):
            font_id = QFontDatabase.addApplicationFont(str(font_dir / filename))
            if font_id >= 0:
                font_ids.append(font_id)
        if font_ids:
            qapp.setFont(QFont("Segoe UI", 9))
    yield
    if font_ids:
        qapp.setFont(original_font)
        for font_id in font_ids:
            QFontDatabase.removeApplicationFont(font_id)


@pytest.fixture
def window(qapp):
    from mainwindow import MainWindow

    widget = MainWindow()
    widget.ui.tabWidget.setCurrentWidget(widget.scraper_tab)
    widget.show()
    qapp.processEvents()
    yield widget
    widget.scraper_tab.task_manager.shutdown(timeout_ms=1000)
    widget.close()
    widget.deleteLater()
    qapp.processEvents()


def assert_logs_reach_content_edge(window):
    scraper = window.scraper_tab
    page_area = scraper.parentWidget().contentsRect()
    assert scraper.geometry() == page_area
    log = scraper.ui.logOutput
    log_right = log.mapTo(scraper.parentWidget(), log.rect().topRight()).x()
    assert page_area.right() - log_right == scraper.layout().contentsMargins().right()


def assert_search_controls_fit(scraper):
    panel = scraper.ui.logOutput.parentWidget()
    controls = [getattr(scraper.ui, name) for name in (
        "lbl_search", "btnClearLog", "lineEditLogFilter", "btnFindPrev",
        "btnFindNext", "lblMatches", "lblFindHits", "btnExportMatches",
        "cbFindCase", "cbFindRegex", "cbFindWhole", "lbl_logs", "logOutput",
    )]
    for control in controls:
        assert control.isVisible(), control.objectName()
        assert panel.contentsRect().contains(control.geometry()), control.objectName()
        assert control.width() >= control.minimumSizeHint().width(), control.objectName()
        assert control.height() >= control.minimumSizeHint().height(), control.objectName()
    for first, second in combinations(controls, 2):
        assert not first.geometry().intersects(second.geometry()), (
            first.objectName(), second.objectName()
        )


@pytest.mark.parametrize("width,height", [
    (1366, 768), (1680, 900), (1800, 800), (1920, 1080), (2560, 1200),
])
def test_search_logs_fill_available_width_without_overlapping_controls(window, qapp, width, height):
    window.resize(width, height)
    qapp.processEvents()

    assert window.size().toTuple() == (width, height)
    assert_logs_reach_content_edge(window)
    assert_search_controls_fit(window.scraper_tab)
    assert window.scraper_tab.ui.taskTable.isVisible()
    assert window.scraper_tab.task_inspector.isVisible()


def test_search_logs_follow_maximize_restore_and_resize(window, qapp):
    window.resize(2200, 1000)
    qapp.processEvents()
    normal_size = window.size()
    assert_logs_reach_content_edge(window)

    window.showMaximized()
    qapp.processEvents()
    assert window.isMaximized()
    assert_logs_reach_content_edge(window)
    # Offscreen can maximize to an 800px screen below the layout minimum;
    # check control fit after restoring to a supported size.

    window.showNormal()
    qapp.processEvents()
    assert not window.isMaximized()
    assert window.size() == normal_size
    assert_logs_reach_content_edge(window)
    assert_search_controls_fit(window.scraper_tab)

    for width in (1800, 2560, 1920):
        window.resize(width, 900)
        qapp.processEvents()
        assert_logs_reach_content_edge(window)
        assert_search_controls_fit(window.scraper_tab)


def drag_handle(splitter, distance, qapp):
    handle = splitter.handle(1)
    center = handle.rect().center()
    QTest.mousePress(handle, Qt.LeftButton, pos=center)
    QTest.mouseMove(handle, center + QPoint(distance, 0))
    QTest.mouseRelease(handle, Qt.LeftButton, pos=center + QPoint(distance, 0))
    qapp.processEvents()


def test_scraper_splitters_remain_draggable_and_search_controls_fit_at_minimum(window, qapp):
    window.resize(2560, 1000)
    qapp.processEvents()
    scraper = window.scraper_tab
    main = scraper.main_splitter
    initial_sizes = main.sizes()

    drag_handle(main, -120, qapp)
    assert main.sizes()[1] > initial_sizes[1]
    assert_logs_reach_content_edge(window)
    assert_search_controls_fit(scraper)

    drag_handle(main, 1000, qapp)
    assert main.sizes()[1] < initial_sizes[1]
    assert_search_controls_fit(scraper)
    assert_logs_reach_content_edge(window)

    inspector = scraper.task_inspector_splitter
    initial_sizes = inspector.sizes()
    drag_handle(inspector, -80, qapp)
    assert inspector.sizes()[1] > initial_sizes[1]
    assert scraper.ui.taskTable.isVisible()
    assert scraper.task_inspector.isVisible()
    assert_search_controls_fit(scraper)
