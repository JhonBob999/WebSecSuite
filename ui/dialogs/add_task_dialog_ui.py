# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'add_task_dialog.ui'
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
from PySide6.QtWidgets import (QApplication, QDialog, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QSizePolicy, QWidget)

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        if not Dialog.objectName():
            Dialog.setObjectName(u"Dialog")
        Dialog.resize(614, 444)
        self.label = QLabel(Dialog)
        self.label.setObjectName(u"label")
        self.label.setGeometry(QRect(0, 0, 81, 21))
        font = QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.label.setFont(font)
        self.lbl_url = QLabel(Dialog)
        self.lbl_url.setObjectName(u"lbl_url")
        self.lbl_url.setGeometry(QRect(10, 40, 49, 21))
        self.lbl_header = QLabel(Dialog)
        self.lbl_header.setObjectName(u"lbl_header")
        self.lbl_header.setGeometry(QRect(10, 70, 51, 21))
        self.lbl_proxy = QLabel(Dialog)
        self.lbl_proxy.setObjectName(u"lbl_proxy")
        self.lbl_proxy.setGeometry(QRect(10, 270, 49, 16))
        self.lbl_useragent = QLabel(Dialog)
        self.lbl_useragent.setObjectName(u"lbl_useragent")
        self.lbl_useragent.setGeometry(QRect(-5, 300, 71, 21))
        self.lbl_useragent.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.lbl_timeout = QLabel(Dialog)
        self.lbl_timeout.setObjectName(u"lbl_timeout")
        self.lbl_timeout.setGeometry(QRect(15, 330, 49, 16))
        self.url_input = QLineEdit(Dialog)
        self.url_input.setObjectName(u"url_input")
        self.url_input.setGeometry(QRect(70, 40, 321, 22))
        self.proxy_input = QLineEdit(Dialog)
        self.proxy_input.setObjectName(u"proxy_input")
        self.proxy_input.setGeometry(QRect(70, 270, 321, 22))
        self.user_agent_input = QLineEdit(Dialog)
        self.user_agent_input.setObjectName(u"user_agent_input")
        self.user_agent_input.setGeometry(QRect(70, 300, 321, 22))
        self.timeout_input = QLineEdit(Dialog)
        self.timeout_input.setObjectName(u"timeout_input")
        self.timeout_input.setGeometry(QRect(70, 330, 321, 22))
        self.btn_ok = QPushButton(Dialog)
        self.btn_ok.setObjectName(u"btn_ok")
        self.btn_ok.setGeometry(QRect(430, 410, 75, 24))
        self.btn_cancel = QPushButton(Dialog)
        self.btn_cancel.setObjectName(u"btn_cancel")
        self.btn_cancel.setGeometry(QRect(530, 410, 75, 24))
        self.header_textedit = QPlainTextEdit(Dialog)
        self.header_textedit.setObjectName(u"header_textedit")
        self.header_textedit.setGeometry(QRect(70, 70, 321, 191))

        self.retranslateUi(Dialog)

        QMetaObject.connectSlotsByName(Dialog)
    # setupUi

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QCoreApplication.translate("Dialog", u"Dialog", None))
        self.label.setText(QCoreApplication.translate("Dialog", u"Add Task", None))
        self.lbl_url.setText(QCoreApplication.translate("Dialog", u"<html><head/><body><p align=\"right\">URL:</p></body></html>", None))
        self.lbl_header.setText(QCoreApplication.translate("Dialog", u"<html><head/><body><p align=\"right\">Headers:</p></body></html>", None))
        self.lbl_proxy.setText(QCoreApplication.translate("Dialog", u"<html><head/><body><p align=\"right\">Proxy:</p></body></html>", None))
        self.lbl_useragent.setText(QCoreApplication.translate("Dialog", u"<html><head/><body><p align=\"right\">User-Agent:</p></body></html>", None))
        self.lbl_timeout.setText(QCoreApplication.translate("Dialog", u"<html><head/><body><p align=\"right\">Timeout:</p></body></html>", None))
        self.btn_ok.setText(QCoreApplication.translate("Dialog", u"OK", None))
        self.btn_cancel.setText(QCoreApplication.translate("Dialog", u"Cancel", None))
    # retranslateUi

