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
from PySide6.QtWidgets import (QApplication, QComboBox, QDialog, QLabel,
    QLineEdit, QPlainTextEdit, QPushButton, QSizePolicy,
    QSpinBox, QWidget)

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        if not Dialog.objectName():
            Dialog.setObjectName(u"Dialog")
        Dialog.resize(614, 444)
        self.lbl_add_task = QLabel(Dialog)
        self.lbl_add_task.setObjectName(u"lbl_add_task")
        self.lbl_add_task.setGeometry(QRect(0, 0, 81, 21))
        font = QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.lbl_add_task.setFont(font)
        self.lbl_url = QLabel(Dialog)
        self.lbl_url.setObjectName(u"lbl_url")
        self.lbl_url.setGeometry(QRect(10, 30, 49, 21))
        font1 = QFont()
        font1.setBold(False)
        self.lbl_url.setFont(font1)
        self.lbl_header = QLabel(Dialog)
        self.lbl_header.setObjectName(u"lbl_header")
        self.lbl_header.setGeometry(QRect(10, 220, 51, 21))
        self.lbl_proxy = QLabel(Dialog)
        self.lbl_proxy.setObjectName(u"lbl_proxy")
        self.lbl_proxy.setGeometry(QRect(10, 80, 49, 16))
        self.lbl_proxy.setFont(font1)
        self.lbl_useragent = QLabel(Dialog)
        self.lbl_useragent.setObjectName(u"lbl_useragent")
        self.lbl_useragent.setGeometry(QRect(10, 130, 71, 21))
        self.lbl_useragent.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.lbl_timeout = QLabel(Dialog)
        self.lbl_timeout.setObjectName(u"lbl_timeout")
        self.lbl_timeout.setGeometry(QRect(10, 170, 51, 21))
        self.url_input = QLineEdit(Dialog)
        self.url_input.setObjectName(u"url_input")
        self.url_input.setGeometry(QRect(10, 50, 321, 22))
        self.proxy_input = QLineEdit(Dialog)
        self.proxy_input.setObjectName(u"proxy_input")
        self.proxy_input.setGeometry(QRect(10, 100, 321, 22))
        self.user_agent_input = QLineEdit(Dialog)
        self.user_agent_input.setObjectName(u"user_agent_input")
        self.user_agent_input.setGeometry(QRect(10, 150, 321, 22))
        self.timeout_input = QLineEdit(Dialog)
        self.timeout_input.setObjectName(u"timeout_input")
        self.timeout_input.setGeometry(QRect(10, 190, 321, 22))
        self.btn_ok = QPushButton(Dialog)
        self.btn_ok.setObjectName(u"btn_ok")
        self.btn_ok.setGeometry(QRect(450, 420, 75, 24))
        self.btn_cancel = QPushButton(Dialog)
        self.btn_cancel.setObjectName(u"btn_cancel")
        self.btn_cancel.setGeometry(QRect(540, 420, 75, 24))
        self.header_textedit = QPlainTextEdit(Dialog)
        self.header_textedit.setObjectName(u"header_textedit")
        self.header_textedit.setGeometry(QRect(10, 240, 321, 201))
        self.lbl_http = QLabel(Dialog)
        self.lbl_http.setObjectName(u"lbl_http")
        self.lbl_http.setGeometry(QRect(400, 50, 91, 20))
        self.http_combox = QComboBox(Dialog)
        self.http_combox.addItem("")
        self.http_combox.addItem("")
        self.http_combox.addItem("")
        self.http_combox.addItem("")
        self.http_combox.setObjectName(u"http_combox")
        self.http_combox.setGeometry(QRect(500, 50, 111, 22))
        self.retries_spin = QSpinBox(Dialog)
        self.retries_spin.setObjectName(u"retries_spin")
        self.retries_spin.setGeometry(QRect(500, 80, 111, 22))
        self.lbl_retires = QLabel(Dialog)
        self.lbl_retires.setObjectName(u"lbl_retires")
        self.lbl_retires.setGeometry(QRect(440, 80, 49, 21))

        self.retranslateUi(Dialog)

        QMetaObject.connectSlotsByName(Dialog)
    # setupUi

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QCoreApplication.translate("Dialog", u"Dialog", None))
        self.lbl_add_task.setText(QCoreApplication.translate("Dialog", u"Add Task", None))
        self.lbl_url.setText(QCoreApplication.translate("Dialog", u"<html><head/><body><p>URL:</p></body></html>", None))
        self.lbl_header.setText(QCoreApplication.translate("Dialog", u"<html><head/><body><p>Headers:</p></body></html>", None))
        self.lbl_proxy.setText(QCoreApplication.translate("Dialog", u"<html><head/><body><p>Proxy:</p></body></html>", None))
        self.lbl_useragent.setText(QCoreApplication.translate("Dialog", u"<html><head/><body><p>User-Agent:</p></body></html>", None))
        self.lbl_timeout.setText(QCoreApplication.translate("Dialog", u"<html><head/><body><p>Timeout:</p></body></html>", None))
        self.btn_ok.setText(QCoreApplication.translate("Dialog", u"OK", None))
        self.btn_cancel.setText(QCoreApplication.translate("Dialog", u"Cancel", None))
        self.lbl_http.setText(QCoreApplication.translate("Dialog", u"<html><head/><body><p align=\"right\">HTTP-Method:</p></body></html>", None))
        self.http_combox.setItemText(0, QCoreApplication.translate("Dialog", u"GET", None))
        self.http_combox.setItemText(1, QCoreApplication.translate("Dialog", u"POST", None))
        self.http_combox.setItemText(2, QCoreApplication.translate("Dialog", u"PUT", None))
        self.http_combox.setItemText(3, QCoreApplication.translate("Dialog", u"HEAD", None))

        self.lbl_retires.setText(QCoreApplication.translate("Dialog", u"<html><head/><body><p align=\"right\">Retries:</p></body></html>", None))
    # retranslateUi

