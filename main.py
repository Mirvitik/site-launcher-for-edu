import sys

from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import QMainWindow, QApplication, QMessageBox
from subprocess import Popen
from disclaimer import DisclaimerDialog
from mainui import Ui_MainWindow
from brochureviewer import HTMLBrochureViewer
import json


class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        with open('data.json') as f:
            try:
                data = json.load(f)
            except Exception:
                f.write('{"attention": true}')
        if data['attention']:
            self.showDisclaimer()
        self.setupUi(self)
        self.image = QPixmap('media/image.png')
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

    def showDisclaimer(self):
        dialog = DisclaimerDialog(self)
        result = dialog.exec()

        if not result == QMessageBox.StandardButton.Yes:
            sys.exit(0)
        else:
            with open('data.json') as f:
                data = json.load(f)
            with open('data.json', 'w') as f:
                data['attention'] = False
                f.write(json.dumps(data))

    def runserver(self):
        if self.server is not None:
            self.pushButton.setText('Включить сервер')
            self.server.terminate()
            self.server = None
        else:
            self.pushButton.setText('Выключить сервер')
            if self.radiosqlinjection.isChecked():
                self.label.setText(
                    f'Сайт доступен по <a href="http://127.0.0.1:{self.spinBox.value()}">http://127.0.0.1:{self.spinBox.value()}</a>')
                self.server = Popen([sys.executable, 'server.py', f'{self.spinBox.value()}'])
                if self.checkBox.isChecked():
                    self.browser = HTMLBrochureViewer()
                    self.browser.show_vulnerability('sqlinjection')
            elif self.radioButton_2.isChecked():
                self.label.setText(
                    f'Сайт доступен по <a href="http://127.0.0.1:{self.spinBox.value()}">http://127.0.0.1:{self.spinBox.value()}</a>')
                self.server = Popen([sys.executable, 'traversal.py', f'{self.spinBox.value()}'])
                if self.checkBox.isChecked():
                    self.browser = HTMLBrochureViewer()
                    self.browser.show_vulnerability('traversal')
            elif self.radioButton.isChecked():
                self.label.setText(
                    f'Сайт доступен по <a href="http://127.0.0.1:{self.spinBox.value()}">http://127.0.0.1:{self.spinBox.value()}</a>')
                self.server = Popen([sys.executable, 'oscommand.py', f'{self.spinBox.value()}'])
                if self.checkBox.isChecked():
                    self.browser = HTMLBrochureViewer()
                    self.browser.show_vulnerability('oscommand')
            elif self.radioButton_3.isChecked():
                self.label.setText(
                    f'Сайт доступен по <a href="http://127.0.0.1:{self.spinBox.value()}">http://127.0.0.1:{self.spinBox.value()}</a>')
                self.server = Popen([sys.executable, 'idor.py', f'{self.spinBox.value()}'])
                if self.checkBox.isChecked():
                    self.browser = HTMLBrochureViewer()
                    self.browser.show_vulnerability('idor')
            else:
                self.label.setText('Выберите тип уязвимости')
                self.pushButton.setText('Включить сервер')

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
