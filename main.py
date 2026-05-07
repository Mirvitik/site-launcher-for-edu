import os
from datetime import datetime
import sys
from pathlib import Path

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import (
    QMainWindow,
    QApplication,
    QMessageBox,
    QFileDialog
)
from subprocess import Popen
from disclaimer import DisclaimerDialog
from mainui import Ui_MainWindow
from brochureviewer import HTMLBrochureViewer
from scanner import FlaskVulnerabilityScanner
import json

import socket


def load_css_inline(css_path):
    """Читает CSS файл и вставляет прямо в HTML"""
    with open(css_path, "r", encoding="utf-8") as f:
        return f.read()


def is_port_in_use(port, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return False
        except socket.error:
            return True


class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        with open("data.json") as f:
            try:
                data = json.load(f)
            except Exception:
                f.write('{"attention": true}')
        if data["attention"]:
            self.showDisclaimer()
        self.setupUi(self)
        self.image = QPixmap("media/image.png")
        self.label_3.setPixmap(self.image)
        self.setWindowTitle("ShowExploit")
        self.setWindowIcon(QIcon("media/img.png"))
        self.pushButton.clicked.connect(self.runserver)
        self.checkBox.setChecked(True)
        self.spinBox.setMinimum(1)
        self.spinBox.setMaximum(65535)
        self.spinBox.setValue(5000)
        self.checkBox.clicked.connect(self.stop)
        self.pushButton_2.clicked.connect(self.scan_vulnerabilities)
        self.label.setOpenExternalLinks(True)
        self.server = None
        self.browser = None

    def scan_vulnerabilities(self):
        folder_path = QFileDialog.getExistingDirectory(
            self,
            "Выберите папку проекта для сканирования",
            "",
            QFileDialog.Option.ShowDirsOnly,
        )
        if not folder_path:
            QMessageBox.information(
                self, "Информация", "Сканирование отменено. Папка проекта не выбрана."
            )
            return
        scanner = FlaskVulnerabilityScanner(folder_path)
        self.generate_html_report(scanner.scan(), folder_path)

    def generate_html_report(self, results, scan_path, output_file="scan_report.html"):
        total_vulns = 0
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        vuln_types_count = {}

        unique_results = {}
        for vuln_type, findings in results.items():
            unique_findings = []
            seen = set()
            for item in findings:
                key = f"{item['file']}_{item['line']}_{item['description']}"
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(item)
                    total_vulns += 1
                    risk = item.get("risk", "MEDIUM")
                    risk_counts[risk] = risk_counts.get(risk, 0) + 1
            if unique_findings:
                vuln_types_count[vuln_type] = len(unique_findings)
                unique_results[vuln_type] = unique_findings

        vuln_titles = {
            "sql_injection": "SQL Инъекции",
            "os_command_injection": "OS Command Injection",
            "path_traversal": "Path Traversal",
            "idor": "IDOR (Insecure Direct Object Reference)",
            "other": "Другие уязвимости",
        }
        risk_badge_class = {
            "CRITICAL": "danger",
            "HIGH": "warning",
            "MEDIUM": "info",
            "LOW": "success",
            "INFO": "secondary",
        }
        print(f"{Path(os.getcwd()).as_posix()}/static/bootstrap.min.css")
        static_path = Path.cwd() / "static"
        base_url = QUrl.fromLocalFile(str(static_path))
        print(base_url)
        css_path = Path.cwd() / "static/bootstrap.min.css"
        css_content = load_css_inline(css_path)
        html_content = f"""<!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Отчет о сканировании уязвимостей</title>
        <style>\n{css_content}\n</style>
    </head>
    <body class="bg-light">
        <div class="container py-4">
            <!-- Header -->
            <div class="bg-primary text-white rounded-3 p-4 mb-4 shadow-sm">
                <h1 class="display-5 fw-bold mb-2">
                    <i class="fas fa-shield-alt me-3"></i>
                    Отчет о сканировании уязвимостей
                </h1>
            </div>

            <!-- Информация о сканировании -->
            <div class="card shadow-sm mb-4">
                <div class="card-header bg-white">
                    <h5 class="mb-0">
                        <i class="fas fa-info-circle text-primary me-2"></i>
                        Информация о сканировании
                    </h5>
                </div>
                <div class="card-body">
                    <div class="row g-3">
                        <div class="col-md-4">
                            <div class="border rounded p-3 bg-light">
                                <small class="text-muted">📂 Путь к проекту</small>
                                <div class="fw-bold text-break">{scan_path}</div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="border rounded p-3 bg-light">
                                <small class="text-muted">📅 Дата сканирования</small>
                                <div class="fw-bold">{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Статистика -->
            <div class="row g-4 mb-4">
                <div class="col-md-3">
                    <div class="card bg-primary text-white shadow-sm h-100">
                        <div class="card-body text-center">
                            <h3 class="display-5 fw-bold mb-0">{total_vulns}</h3>
                            <p class="mb-0">Всего уязвимостей</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-danger text-white shadow-sm h-100">
                        <div class="card-body text-center">
                            <h3 class="display-5 fw-bold mb-0">{risk_counts.get('CRITICAL', 0)}</h3>
                            <p class="mb-0">Критические (CRITICAL)</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-warning text-dark shadow-sm h-100">
                        <div class="card-body text-center">
                            <h3 class="display-5 fw-bold mb-0">{risk_counts.get('HIGH', 0)}</h3>
                            <p class="mb-0">Высокие (HIGH)</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-info text-white shadow-sm h-100">
                        <div class="card-body text-center">
                            <h3 class="display-5 fw-bold mb-0">{risk_counts.get('MEDIUM', 0)}</h3>
                            <p class="mb-0">Средние (MEDIUM)</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-secondary text-white shadow-sm h-100">
                        <div class="card-body text-center">
                            <h3 class="display-5 fw-bold mb-0">{risk_counts.get('INFO', 0)}</h3>
                            <p class="mb-0">Возможные (INFO)</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Распределение по типам -->
            <div class="card shadow-sm mb-4">
                <div class="card-header bg-white">
                    <h5 class="mb-0">
                        <i class="fas fa-chart-pie text-primary me-2"></i>
                        Распределение по типам уязвимостей
                    </h5>
                </div>
                <div class="card-body">
    """

        for vuln_type, count in vuln_types_count.items():
            percentage = (count / total_vulns * 100) if total_vulns > 0 else 0
            title = vuln_titles.get(vuln_type, vuln_type)

            html_content += f"""
                    <div class="mb-3">
                        <div class="d-flex justify-content-between mb-1">
                            <span>{title}</span>
                            <span class="fw-bold">{count} ({percentage:.1f}%)</span>
                        </div>
                        <div class="progress">
                            <div class="progress-bar bg-primary" 
                                 role="progressbar" 
                                 style="width: {percentage}%" 
                                 aria-valuenow="{percentage}" 
                                 aria-valuemin="0" 
                                 aria-valuemax="100">
                            </div>
                        </div>
                    </div>
    """

        html_content += """
                </div>
            </div>

            <!-- Результаты сканирования -->
            <div class="card shadow-sm mb-4">
                <div class="card-header bg-white">
                    <h5 class="mb-0">
                        <i class="fas fa-list text-primary me-2"></i>
                        Детальные результаты сканирования
                    </h5>
                </div>
                <div class="card-body p-0">
                    <div class="accordion" id="vulnerabilityAccordion">
    """

        first = True
        for vuln_type, findings in unique_results.items():
            if findings:
                type_title = vuln_titles.get(vuln_type, vuln_type)
                accordion_id = f"accordion_{vuln_type}"
                show_class = "show" if first else ""
                first = False

                html_content += f"""
                        <div class="accordion-item">
                            <h2 class="accordion-header">
                                <button class="accordion-button {'' if show_class else 'collapsed'}" 
                                        type="button" 
                                        data-bs-toggle="collapse" 
                                        data-bs-target="#{accordion_id}" 
                                        aria-expanded="{'true' if show_class else 'false'}" 
                                        aria-controls="{accordion_id}">
                                    <i class="fas fa-bug me-2"></i>
                                    {type_title}
                                    <span class="badge bg-secondary ms-2">{len(findings)}</span>
                                </button>
                            </h2>
                            <div id="{accordion_id}" 
                                 class="accordion-collapse collapse {show_class}" 
                                 data-bs-parent="#vulnerabilityAccordion">
                                <div class="accordion-body p-0">
                                    <div class="list-group list-group-flush">
    """

                for item in findings:
                    risk = item.get("risk", "MEDIUM")
                    badge_class = risk_badge_class.get(risk, "secondary")

                    html_content += f"""
                                        <div class="list-group-item">
                                            <div class="d-flex justify-content-between align-items-start mb-2">
                                                <span class="badge bg-{badge_class}">Уровень: {risk}</span>
                                                <small class="text-muted">
                                                    <i class="fas fa-hashtag"></i> Строка {item.get('line', 'N/A')}
                                                </small>
                                            </div>
                                            <div class="mb-2">
                                                <i class="fas fa-file-code text-primary me-1"></i>
                                                <code class="small text-break">{item.get('file', 'N/A')}</code>
                                            </div>
                                            <div class="mb-2">
                                                <i class="fas fa-exclamation-triangle text-warning me-1"></i>
                                                <strong>Описание:</strong> {item.get('description', 'N/A')}
                                            </div>
                                            <div>
                                                <i class="fas fa-code text-success me-1"></i>
                                                <strong>Код:</strong>
                                                <pre class="bg-dark text-light p-2 rounded mt-2 mb-0 overflow-auto"><code style="font-size: 0.85rem;">{item.get('code', 'N/A')}</code></pre>
                                            </div>
                                        </div>
    """

                html_content += """
                                    </div>
                                </div>
                            </div>
                        </div>
    """

        html_content += """
                    </div>
                </div>
            </div>

            <!-- Рекомендации -->
            <div class="card shadow-sm mb-4">
                <div class="card-header bg-white">
                    <h5 class="mb-0">
                        <i class="fas fa-lightbulb text-warning me-2"></i>
                        Рекомендации по исправлению
                    </h5>
                </div>
                <div class="card-body">
                    <div class="row">
    """

        if "idor" in unique_results:
            html_content += """
                        <div class="col-md-6 mb-3">
                            <div class="card border-danger h-100">
                                <div class="card-body">
                                    <h6 class="card-title text-danger">
                                        <i class="fas fa-key me-2"></i>IDOR
                                    </h6>
                                    <ul class="small mb-0">
                                        <li>Внедрите проверку прав доступа перед выдачей данных</li>
                                        <li>Используйте Flask-Login для аутентификации</li>
                                        <li>Проверяйте доступ пользователя к объекту</li>
                                        <li><code>if current_user.id != user_id: abort(403)</code></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
    """

        if "sql_injection" in unique_results:
            html_content += """
                        <div class="col-md-6 mb-3">
                            <div class="card border-warning h-100">
                                <div class="card-body">
                                    <h6 class="card-title text-warning">
                                        <i class="fas fa-database me-2"></i>SQL Инъекции
                                    </h6>
                                    <ul class="small mb-0">
                                        <li>Используйте параметризованные запросы</li>
                                        <li>Применяйте ORM (SQLAlchemy)</li>
                                        <li><code>cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))</code></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
    """

        if "os_command_injection" in unique_results:
            html_content += """
                        <div class="col-md-6 mb-3">
                            <div class="card border-danger h-100">
                                <div class="card-body">
                                    <h6 class="card-title text-danger">
                                        <i class="fas fa-terminal me-2"></i>OS Command Injection
                                    </h6>
                                    <ul class="small mb-0">
                                        <li>НЕ используйте <code>shell=True</code> в subprocess</li>
                                        <li>Используйте список аргументов вместо строки</li>
                                        <li><code>subprocess.run(['ping', '-c', '1', host])</code></li>
                                        <li>Валидируйте входные данные</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
    """

        if "path_traversal" in unique_results:
            html_content += """
                        <div class="col-md-6 mb-3">
                            <div class="card border-warning h-100">
                                <div class="card-body">
                                    <h6 class="card-title text-warning">
                                        <i class="fas fa-folder-open me-2"></i>Path Traversal
                                    </h6>
                                    <ul class="small mb-0">
                                        <li>Используйте <code>send_from_directory</code> вместо <code>send_file</code></li>
                                        <li>Применяйте <code>secure_filename()</code></li>
                                        <li><code>return send_from_directory('images/', secure_filename(filename))</code></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
    """

        if total_vulns == 0:
            html_content += """
                        <div class="col-12">
                            <div class="alert alert-success">
                                <i class="fas fa-check-circle me-2"></i>
                                Уязвимостей не найдено! Продолжайте следовать практикам безопасного программирования.
                            </div>
                        </div>
    """

        html_content += """
                    </div>
                </div>
            </div>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
        if self.checkBox_2.isChecked():
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Сохранить результат",
                "results.html",
                "HTML файлы (*.html);;Все файлы (*.*)",
            )
            if file_path:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(html_content)
                QMessageBox.information(
                    self, "Сохранение", f"Файл сохранен: {file_path}"
                )
                self.browser = HTMLBrochureViewer()
                self.browser.show_html_from_variable(html_content)
                return file_path
            else:
                QMessageBox.information(self, "Сохранение", "Сохранение отменено")
                return None
        self.browser = HTMLBrochureViewer()
        self.browser.show_html_from_variable(html_content)

        return None

    def showDisclaimer(self):
        dialog = DisclaimerDialog(self)
        result = dialog.exec()

        if not result == QMessageBox.StandardButton.Yes:
            sys.exit(0)
        else:
            with open("data.json") as f:
                data = json.load(f)
            with open("data.json", "w") as f:
                data["attention"] = False
                f.write(json.dumps(data))

    def runserver(self):
        if self.server is not None:
            self.pushButton.setText("Запустить сайт")
            self.label.setText("Нажмите на кнопку для запуска сайта")
            self.server.terminate()
            self.server = None
        else:
            self.pushButton.setText("Выключить сайт")
            if is_port_in_use(self.spinBox.value()):
                self.label.setText(
                    "Данный порт занят, выберите другое значение для порта"
                )
            elif self.radiosqlinjection.isChecked():
                self.label.setText(
                    f'Сайт доступен по <a href="http://127.0.0.1:{self.spinBox.value()}">http://127.0.0.1:{self.spinBox.value()}</a>'
                )
                self.server = Popen(
                    [sys.executable, "server.py", f"{self.spinBox.value()}"]
                )
                if self.checkBox.isChecked():
                    self.browser = HTMLBrochureViewer()
                    self.browser.show_vulnerability("sqlinjection")
            elif self.radioButton_2.isChecked():
                self.label.setText(
                    f'Сайт доступен по <a href="http://127.0.0.1:{self.spinBox.value()}">http://127.0.0.1:{self.spinBox.value()}</a>'
                )
                self.server = Popen(
                    [sys.executable, "traversal.py", f"{self.spinBox.value()}"]
                )
                if self.checkBox.isChecked():
                    self.browser = HTMLBrochureViewer()
                    self.browser.show_vulnerability("traversal")
            elif self.radioButton.isChecked():
                self.label.setText(
                    f'Сайт доступен по <a href="http://127.0.0.1:{self.spinBox.value()}">http://127.0.0.1:{self.spinBox.value()}</a>'
                )
                self.server = Popen(
                    [sys.executable, "oscommand.py", f"{self.spinBox.value()}"]
                )
                if self.checkBox.isChecked():
                    self.browser = HTMLBrochureViewer()
                    self.browser.show_vulnerability("oscommand")
            elif self.radioButton_3.isChecked():
                self.label.setText(
                    f'Сайт доступен по <a href="http://127.0.0.1:{self.spinBox.value()}">http://127.0.0.1:{self.spinBox.value()}</a>'
                )
                self.server = Popen(
                    [sys.executable, "idor.py", f"{self.spinBox.value()}"]
                )
                if self.checkBox.isChecked():
                    self.browser = HTMLBrochureViewer()
                    self.browser.show_vulnerability("idor")
            else:
                self.label.setText("Выберите тип уязвимости")
                self.pushButton.setText("Запустить сайт")

    def stop(self):
        if self.server is not None:
            self.server.terminate()

    def closeEvent(self, e):
        if self.server is not None:
            self.server.terminate()


def except_hook(cls, exception, traceback):
    sys.__excepthook__(cls, exception, traceback)


sys.excepthook = except_hook

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(
        """QMainWindow { background-color: black; } QWidget { color: white; }"""
    )
    window = MainWindow()
    window.setFixedSize(window.width(), window.height())
    window.show()
    app.exec()
