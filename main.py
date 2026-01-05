import os
import sys

from PyQt6.QtCore import QUrl
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import QMainWindow, QApplication, QWidget, QVBoxLayout
from PyQt6 import QtCore, QtWidgets
from subprocess import Popen


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label_2 = QtWidgets.QLabel(parent=self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(11, 131, 231, 31))
        self.label_2.setObjectName("label_2")
        self.radiosqlinjection = QtWidgets.QRadioButton(parent=self.centralwidget)
        self.radiosqlinjection.setGeometry(QtCore.QRect(11, 180, 102, 20))
        self.radiosqlinjection.setObjectName("radiosqlinjection")
        self.radioButton = QtWidgets.QRadioButton(parent=self.centralwidget)
        self.radioButton.setGeometry(QtCore.QRect(11, 207, 168, 20))
        self.radioButton.setObjectName("radioButton")
        self.radioButton_2 = QtWidgets.QRadioButton(parent=self.centralwidget)
        self.radioButton_2.setGeometry(QtCore.QRect(11, 234, 201, 20))
        self.radioButton_2.setObjectName("radioButton_2")
        self.radioButton_3 = QtWidgets.QRadioButton(parent=self.centralwidget)
        self.radioButton_3.setGeometry(QtCore.QRect(11, 261, 221, 20))
        self.radioButton_3.setObjectName("radioButton_3")
        self.radioButton_4 = QtWidgets.QRadioButton(parent=self.centralwidget)
        self.radioButton_4.setGeometry(QtCore.QRect(11, 288, 95, 20))
        self.radioButton_4.setObjectName("radioButton_4")
        self.label = QtWidgets.QLabel(parent=self.centralwidget)
        self.label.setGeometry(QtCore.QRect(10, 430, 311, 21))
        self.label.setObjectName("label")
        self.checkBox = QtWidgets.QCheckBox(parent=self.centralwidget)
        self.checkBox.setGeometry(QtCore.QRect(11, 483, 317, 20))
        self.checkBox.setObjectName("checkBox")
        self.pushButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(11, 510, 331, 28))
        self.pushButton.setObjectName("pushButton")
        self.label_3 = QtWidgets.QLabel(parent=self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(350, 50, 400, 400))
        self.label_3.setObjectName("label_3")
        self.spinBox = QtWidgets.QSpinBox(parent=self.centralwidget)
        self.spinBox.setGeometry(QtCore.QRect(20, 370, 201, 22))
        self.spinBox.setObjectName("spinBox")
        self.label_4 = QtWidgets.QLabel(parent=self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(20, 340, 181, 16))
        self.label_4.setObjectName("label_4")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(parent=MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 26))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(parent=MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label_2.setText(_translate("MainWindow", "Создать сайт с"))
        self.radiosqlinjection.setText(_translate("MainWindow", "SQL injection"))
        self.radioButton.setText(_translate("MainWindow", "Command injection (OS)"))
        self.radioButton_2.setText(_translate("MainWindow", "Directory Traversal (LFI/RFI)"))
        self.radioButton_3.setText(_translate("MainWindow", "Broken Access Control (IDOR)"))
        self.radioButton_4.setText(_translate("MainWindow", "RadioButton"))
        self.label.setText(_translate("MainWindow", "Сделайте что-нибудь"))
        self.checkBox.setText(_translate("MainWindow", "Показать документацию брошюру по уязвимости"))
        self.pushButton.setText(_translate("MainWindow", "Запустить сервер"))
        self.label_3.setText(_translate("MainWindow", "TextLabel"))
        self.label_4.setText(_translate("MainWindow", "Изменение порта сайта"))


class HTMLBrochureViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Брошюра')
        self.image = QPixmap('media/image.png')
        self.setWindowIcon(QIcon('media/img.png'))
        self.layout = QVBoxLayout()
        self.browser = QWebEngineView()
        self.layout.addWidget(self.browser)
        self.setLayout(self.layout)

    def show_vulnerability(self, vuln_name):
        html_path = f"brochures/{vuln_name}.html"
        absolute_path = os.path.abspath(html_path)
        self.browser.load(QUrl.fromLocalFile(absolute_path))
        self.show()


class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.image = QPixmap('data/image.png')
        self.label_3.setPixmap(self.image)
        self.setWindowTitle('Генерация сайта с уязвимостью')
        self.setWindowIcon(QIcon('media/img.png'))
        self.pushButton.clicked.connect(self.runserver)
        self.checkBox.setChecked(True)
        self.spinBox.setMinimum(1)
        self.spinBox.setMaximum(65535)
        self.spinBox.setValue(5000)
        self.checkBox.clicked.connect(self.stop)
        self.label.setOpenExternalLinks(True)
        self.server = None
        self.browser = None

    def runserver(self):
        if self.server is not None:
            self.pushButton.setText('Включить сервер')
            self.server.terminate()
            self.server = None
        else:
            self.pushButton.setText('Выключить сервер')
            if self.radiosqlinjection.isChecked():
                self.label.setText('Сайт доступен по <a href="http://127.0.0.1:5000">http://127.0.0.1:5000</a>')
                self.server = Popen([sys.executable, 'server.py'])
                if self.checkBox.isChecked():
                    self.browser = HTMLBrochureViewer()
                    self.browser.show_vulnerability('sqlinjection')
            elif self.radioButton_2.isChecked():
                self.label.setText('Сайт доступен по <a href="http://127.0.0.1:5000">http://127.0.0.1:5000</a>')
                self.server = Popen([sys.executable, 'traversal.py'])
                if self.checkBox.isChecked():
                    self.browser = HTMLBrochureViewer()
                    self.browser.show_vulnerability('traversal')
            else:
                self.label.setText('Выберите тип уязвимости')
                self.pushButton.setText('Запустить сервер')

    def stop(self):
        if self.server is not None:
            self.server.terminate()

    def closeEvent(self, e):
        if self.server is not None:
            self.server.terminate()


def except_hook(cls, exception, traceback):
    sys.__excepthook__(cls, exception, traceback)


sys.excepthook = except_hook

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyleSheet("""QMainWindow { background-color: black; } """)
    window = MainWindow()
    window.setFixedSize(window.width(), window.height())
    window.show()
    app.exec()
