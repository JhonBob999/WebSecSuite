# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'scraper_panel.ui'
##
## Created by: Qt User Interface Compiler version 6.9.1
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QHeaderView, QLabel, QPlainTextEdit,
    QPushButton, QSizePolicy, QTableWidget, QTableWidgetItem,
    QToolButton, QWidget)

class Ui_scraper_panel(object):
    def setupUi(self, scraper_panel):
        if not scraper_panel.objectName():
            scraper_panel.setObjectName(u"scraper_panel")
        scraper_panel.resize(1680, 899)
        scraper_panel.setMaximumSize(QSize(1680, 16777215))
        self.logOutput = QPlainTextEdit(scraper_panel)
        self.logOutput.setObjectName(u"logOutput")
        self.logOutput.setGeometry(QRect(880, 455, 781, 421))
        self.logOutput.setReadOnly(True)
        self.lbl_logs = QLabel(scraper_panel)
        self.lbl_logs.setObjectName(u"lbl_logs")
        self.lbl_logs.setGeometry(QRect(1620, 450, 51, 31))
        font = QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.lbl_logs.setFont(font)
        self.lbl_tasks = QLabel(scraper_panel)
        self.lbl_tasks.setObjectName(u"lbl_tasks")
        self.lbl_tasks.setGeometry(QRect(10, 10, 81, 31))
        font1 = QFont()
        font1.setPointSize(15)
        font1.setBold(True)
        self.lbl_tasks.setFont(font1)
        self.taskTable = QTableWidget(scraper_panel)
        if (self.taskTable.columnCount() < 7):
            self.taskTable.setColumnCount(7)
        __qtablewidgetitem = QTableWidgetItem()
        self.taskTable.setHorizontalHeaderItem(0, __qtablewidgetitem)
        __qtablewidgetitem1 = QTableWidgetItem()
        self.taskTable.setHorizontalHeaderItem(1, __qtablewidgetitem1)
        __qtablewidgetitem2 = QTableWidgetItem()
        self.taskTable.setHorizontalHeaderItem(2, __qtablewidgetitem2)
        __qtablewidgetitem3 = QTableWidgetItem()
        self.taskTable.setHorizontalHeaderItem(3, __qtablewidgetitem3)
        __qtablewidgetitem4 = QTableWidgetItem()
        self.taskTable.setHorizontalHeaderItem(4, __qtablewidgetitem4)
        __qtablewidgetitem5 = QTableWidgetItem()
        self.taskTable.setHorizontalHeaderItem(5, __qtablewidgetitem5)
        __qtablewidgetitem6 = QTableWidgetItem()
        self.taskTable.setHorizontalHeaderItem(6, __qtablewidgetitem6)
        self.taskTable.setObjectName(u"taskTable")
        self.taskTable.setGeometry(QRect(10, 40, 861, 421))
        self.taskTable.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.taskTable.horizontalHeader().setStretchLastSection(True)
        self.btnExport = QPushButton(scraper_panel)
        self.btnExport.setObjectName(u"btnExport")
        self.btnExport.setGeometry(QRect(330, 470, 75, 24))
        self.btnDelete = QPushButton(scraper_panel)
        self.btnDelete.setObjectName(u"btnDelete")
        self.btnDelete.setGeometry(QRect(250, 470, 75, 24))
        self.btnStop = QPushButton(scraper_panel)
        self.btnStop.setObjectName(u"btnStop")
        self.btnStop.setGeometry(QRect(170, 470, 75, 24))
        self.btnStart = QPushButton(scraper_panel)
        self.btnStart.setObjectName(u"btnStart")
        self.btnStart.setGeometry(QRect(90, 470, 75, 24))
        self.btnAddTask = QPushButton(scraper_panel)
        self.btnAddTask.setObjectName(u"btnAddTask")
        self.btnAddTask.setGeometry(QRect(10, 470, 75, 24))
        self.btnClearLog = QToolButton(scraper_panel)
        self.btnClearLog.setObjectName(u"btnClearLog")
        self.btnClearLog.setGeometry(QRect(1615, 430, 48, 22))
        self.btnPause = QPushButton(scraper_panel)
        self.btnPause.setObjectName(u"btnPause")
        self.btnPause.setGeometry(QRect(90, 500, 75, 24))
        self.btnResume = QPushButton(scraper_panel)
        self.btnResume.setObjectName(u"btnResume")
        self.btnResume.setGeometry(QRect(10, 500, 75, 24))

        self.retranslateUi(scraper_panel)

        QMetaObject.connectSlotsByName(scraper_panel)
    # setupUi

    def retranslateUi(self, scraper_panel):
        scraper_panel.setWindowTitle(QCoreApplication.translate("scraper_panel", u"Form", None))
        self.lbl_logs.setText(QCoreApplication.translate("scraper_panel", u"Logs", None))
        self.lbl_tasks.setText(QCoreApplication.translate("scraper_panel", u"Tasks", None))
        ___qtablewidgetitem = self.taskTable.horizontalHeaderItem(0)
        ___qtablewidgetitem.setText(QCoreApplication.translate("scraper_panel", u"URL", None));
        ___qtablewidgetitem1 = self.taskTable.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(QCoreApplication.translate("scraper_panel", u"Status", None));
        ___qtablewidgetitem2 = self.taskTable.horizontalHeaderItem(2)
        ___qtablewidgetitem2.setText(QCoreApplication.translate("scraper_panel", u"Code", None));
        ___qtablewidgetitem3 = self.taskTable.horizontalHeaderItem(3)
        ___qtablewidgetitem3.setText(QCoreApplication.translate("scraper_panel", u"Time", None));
        ___qtablewidgetitem4 = self.taskTable.horizontalHeaderItem(4)
        ___qtablewidgetitem4.setText(QCoreApplication.translate("scraper_panel", u"Results", None));
        ___qtablewidgetitem5 = self.taskTable.horizontalHeaderItem(5)
        ___qtablewidgetitem5.setText(QCoreApplication.translate("scraper_panel", u"Cookies", None));
        ___qtablewidgetitem6 = self.taskTable.horizontalHeaderItem(6)
        ___qtablewidgetitem6.setText(QCoreApplication.translate("scraper_panel", u"Params", None));
        self.btnExport.setText(QCoreApplication.translate("scraper_panel", u"Export", None))
        self.btnDelete.setText(QCoreApplication.translate("scraper_panel", u"Delete", None))
        self.btnStop.setText(QCoreApplication.translate("scraper_panel", u"Stop", None))
        self.btnStart.setText(QCoreApplication.translate("scraper_panel", u"Start", None))
        self.btnAddTask.setText(QCoreApplication.translate("scraper_panel", u"Add Task", None))
        self.btnClearLog.setText(QCoreApplication.translate("scraper_panel", u"CLEAR", None))
        self.btnPause.setText(QCoreApplication.translate("scraper_panel", u"Pause", None))
        self.btnResume.setText(QCoreApplication.translate("scraper_panel", u"Resume", None))
    # retranslateUi

