# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'data_preview_dialog.ui'
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
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QDialog, QHeaderView,
    QLineEdit, QSizePolicy, QTableWidget, QTableWidgetItem,
    QToolButton, QWidget)

class Ui_DataPreviewDialog(object):
    def setupUi(self, DataPreviewDialog):
        if not DataPreviewDialog.objectName():
            DataPreviewDialog.setObjectName(u"DataPreviewDialog")
        DataPreviewDialog.resize(1465, 865)
        self.btnLoadAll = QToolButton(DataPreviewDialog)
        self.btnLoadAll.setObjectName(u"btnLoadAll")
        self.btnLoadAll.setGeometry(QRect(10, 500, 91, 23))
        self.btnLoadSelected = QToolButton(DataPreviewDialog)
        self.btnLoadSelected.setObjectName(u"btnLoadSelected")
        self.btnLoadSelected.setGeometry(QRect(110, 500, 101, 23))
        self.btnRefresh = QToolButton(DataPreviewDialog)
        self.btnRefresh.setObjectName(u"btnRefresh")
        self.btnRefresh.setGeometry(QRect(220, 500, 91, 23))
        self.btnExport = QToolButton(DataPreviewDialog)
        self.btnExport.setObjectName(u"btnExport")
        self.btnExport.setGeometry(QRect(320, 500, 101, 23))
        self.lineSearch = QLineEdit(DataPreviewDialog)
        self.lineSearch.setObjectName(u"lineSearch")
        self.lineSearch.setGeometry(QRect(10, 50, 211, 24))
        self.tablePreview = QTableWidget(DataPreviewDialog)
        self.tablePreview.setObjectName(u"tablePreview")
        self.tablePreview.setGeometry(QRect(10, 80, 851, 411))
        self.tablePreview.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tablePreview.setAlternatingRowColors(True)
        self.tablePreview.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tablePreview.setSortingEnabled(True)

        self.retranslateUi(DataPreviewDialog)

        QMetaObject.connectSlotsByName(DataPreviewDialog)
    # setupUi

    def retranslateUi(self, DataPreviewDialog):
        DataPreviewDialog.setWindowTitle(QCoreApplication.translate("DataPreviewDialog", u"Dialog", None))
        self.btnLoadAll.setText(QCoreApplication.translate("DataPreviewDialog", u"Load All", None))
        self.btnLoadSelected.setText(QCoreApplication.translate("DataPreviewDialog", u"Load Selected", None))
        self.btnRefresh.setText(QCoreApplication.translate("DataPreviewDialog", u"Refresh", None))
        self.btnExport.setText(QCoreApplication.translate("DataPreviewDialog", u"Export", None))
    # retranslateUi

