from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QMessageBox


class DisclaimerDialog(QMessageBox):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("ВАЖНОЕ ПРЕДУПРЕЖДЕНИЕ")
        self.setWindowIcon(QIcon("media/img.png"))

        disclaimer_text = """
        <html>
        <head>
        <style>
        h2 { color: #d32f2f; }
        .warning { color: #f57c00; font-weight: bold; }
        .normal { margin: 10px 0; }
        </style>
        </head>
        <body>
        <h2>ПРЕДУПРЕЖДЕНИЕ ОБ ОТВЕТСТВЕННОМ ИСПОЛЬЗОВАНИИ</h2>

        <p class="normal">Данная программа предоставляется исключительно в <span class="warning">учебных и исследовательских целях</span>.</p>

        <p class="normal"><b>Вы обязуетесь:</b></p>
        <ul>
            <li>Использовать программу только в законных целях</li>
            <li>Не проводить атаки на системы без явного разрешения</li>
            <li>Соблюдать все применимые законы и нормативные акты</li>
            <li>Использовать знания только для улучшения безопасности</li>
        </ul>

        <p class="normal"><b>Запрещается:</b></p>
        <ul>
            <li>Использовать программу для взлома или несанкционированного доступа</li>
            <li>Нарушать конфиденциальность других лиц</li>
            <li>Наносить ущерб компьютерным системам</li>
            <li>Распространять вредоносное программное обеспечение</li>
        </ul>

        <p class="normal">Разработчик не несет ответственности за неправомерное использование данной программы.</p>

        <p style="color: #388e3c; font-weight: bold;">
        Продолжая, вы подтверждаете, что понимаете и соглашаетесь с этими условиями.
        </p>
        </body>
        </html>
        """

        self.setText(disclaimer_text)
        self.setTextFormat(Qt.TextFormat.RichText)

        self.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        self.button(QMessageBox.StandardButton.Yes).setText(
            "Я согласен и принимаю условия"
        )
        self.button(QMessageBox.StandardButton.No).setText("Отказаться и выйти")

        self.setIcon(QMessageBox.Icon.Warning)

        self.setMinimumSize(600, 500)
