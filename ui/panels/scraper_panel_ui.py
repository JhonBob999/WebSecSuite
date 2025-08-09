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
from PySide6.QtWidgets import (QApplication, QHBoxLayout, QHeaderView, QLabel,
    QPlainTextEdit, QPushButton, QSizePolicy, QTableWidget,
    QTableWidgetItem, QToolButton, QVBoxLayout, QWidget)

class Ui_scraper_panel(object):
    def setupUi(self, scraper_panel):
        if not scraper_panel.objectName():
            scraper_panel.setObjectName(u"scraper_panel")
        scraper_panel.resize(1668, 899)
        self.horizontalLayout = QHBoxLayout(scraper_panel)
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.lbl_tasks = QLabel(scraper_panel)
        self.lbl_tasks.setObjectName(u"lbl_tasks")

        self.verticalLayout.addWidget(self.lbl_tasks)

        self.taskTable = QTableWidget(scraper_panel)
        if (self.taskTable.columnCount() < 2):
            self.taskTable.setColumnCount(2)
        __qtablewidgetitem = QTableWidgetItem()
        self.taskTable.setHorizontalHeaderItem(0, __qtablewidgetitem)
        __qtablewidgetitem1 = QTableWidgetItem()
        self.taskTable.setHorizontalHeaderItem(1, __qtablewidgetitem1)
        self.taskTable.setObjectName(u"taskTable")
        self.taskTable.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.taskTable.horizontalHeader().setStretchLastSection(True)

        self.verticalLayout.addWidget(self.taskTable)

        self.lbl_logs = QLabel(scraper_panel)
        self.lbl_logs.setObjectName(u"lbl_logs")

        self.verticalLayout.addWidget(self.lbl_logs)

        self.horizontalLayout_3 = QHBoxLayout()
        self.horizontalLayout_3.setObjectName(u"horizontalLayout_3")
        self.btnInfo = QToolButton(scraper_panel)
        self.btnInfo.setObjectName(u"btnInfo")

        self.horizontalLayout_3.addWidget(self.btnInfo)

        self.btnWarn = QToolButton(scraper_panel)
        self.btnWarn.setObjectName(u"btnWarn")

        self.horizontalLayout_3.addWidget(self.btnWarn)

        self.btnError = QToolButton(scraper_panel)
        self.btnError.setObjectName(u"btnError")

        self.horizontalLayout_3.addWidget(self.btnError)

        self.btnClearLog = QToolButton(scraper_panel)
        self.btnClearLog.setObjectName(u"btnClearLog")

        self.horizontalLayout_3.addWidget(self.btnClearLog)


        self.verticalLayout.addLayout(self.horizontalLayout_3)

        self.logOutput = QPlainTextEdit(scraper_panel)
        self.logOutput.setObjectName(u"logOutput")
        self.logOutput.setReadOnly(True)

        self.verticalLayout.addWidget(self.logOutput)


        self.horizontalLayout.addLayout(self.verticalLayout)

        self.verticalLayout_2 = QVBoxLayout()
        self.verticalLayout_2.setSpacing(0)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.btnAddTask = QPushButton(scraper_panel)
        self.btnAddTask.setObjectName(u"btnAddTask")

        self.verticalLayout_2.addWidget(self.btnAddTask)

        self.btnStart = QPushButton(scraper_panel)
        self.btnStart.setObjectName(u"btnStart")

        self.verticalLayout_2.addWidget(self.btnStart)

        self.btnStop = QPushButton(scraper_panel)
        self.btnStop.setObjectName(u"btnStop")

        self.verticalLayout_2.addWidget(self.btnStop)

        self.btnDelete = QPushButton(scraper_panel)
        self.btnDelete.setObjectName(u"btnDelete")

        self.verticalLayout_2.addWidget(self.btnDelete)

        self.btnExport = QPushButton(scraper_panel)
        self.btnExport.setObjectName(u"btnExport")

        self.verticalLayout_2.addWidget(self.btnExport)


        self.horizontalLayout.addLayout(self.verticalLayout_2)


        self.retranslateUi(scraper_panel)

        QMetaObject.connectSlotsByName(scraper_panel)
    # setupUi

    def retranslateUi(self, scraper_panel):
        scraper_panel.setWindowTitle(QCoreApplication.translate("scraper_panel", u"Form", None))
        self.lbl_tasks.setText(QCoreApplication.translate("scraper_panel", u"Tasks", None))
        ___qtablewidgetitem = self.taskTable.horizontalHeaderItem(0)
        ___qtablewidgetitem.setText(QCoreApplication.translate("scraper_panel", u"URL", None));
        ___qtablewidgetitem1 = self.taskTable.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(QCoreApplication.translate("scraper_panel", u"Status", None));
        self.lbl_logs.setText(QCoreApplication.translate("scraper_panel", u"Logs", None))
        self.btnInfo.setText(QCoreApplication.translate("scraper_panel", u"INFO", None))
        self.btnWarn.setText(QCoreApplication.translate("scraper_panel", u"WARN", None))
        self.btnError.setText(QCoreApplication.translate("scraper_panel", u"ERROR", None))
        self.btnClearLog.setText(QCoreApplication.translate("scraper_panel", u"CLEAR", None))
        self.btnAddTask.setText(QCoreApplication.translate("scraper_panel", u"Add Task", None))
        self.btnStart.setText(QCoreApplication.translate("scraper_panel", u"Start", None))
        self.btnStop.setText(QCoreApplication.translate("scraper_panel", u"Stop", None))
        self.btnDelete.setText(QCoreApplication.translate("scraper_panel", u"Delete", None))
        self.btnExport.setText(QCoreApplication.translate("scraper_panel", u"Export", None))
    # retranslateUi

