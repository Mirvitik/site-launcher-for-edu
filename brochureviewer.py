import os

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QPixmap, QIcon
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import QWidget, QVBoxLayout


class HTMLBrochureViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Гайд")
        self.image = QPixmap("media/image.png")
        self.setWindowIcon(QIcon("media/img.png"))
        self.layout = QVBoxLayout()
        self.browser = QWebEngineView()
        self.layout.addWidget(self.browser)
        self.setLayout(self.layout)

    def show_vulnerability(self, vuln_name):
        html_path = f"brochures/{vuln_name}.html"
        absolute_path = os.path.abspath(html_path)
        self.browser.load(QUrl.fromLocalFile(absolute_path))
        self.show()

    def show_res(self, file_path):
        self.setWindowTitle("Результат")
        absolute_path = os.path.abspath(file_path)
        self.browser.load(QUrl.fromLocalFile(absolute_path))
        self.show()

    def show_html_from_variable(self, html_content):
        self.setWindowTitle('Отчёт')
        self.browser.setHtml(html_content)
        self.show()
