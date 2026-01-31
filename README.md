## Проект "Лаунчер сайтов с уязвимостями"

Перед запуском убедитесь, что у вас установлены:

- [Python релизные версии от 3.10 до 3.12 включительно](https://www.python.org/downloads/)
- [Последняя версия git](https://git-scm.com/install/???Download??git)
- pip (устанавливается вместе с питоном)
- virtualenv (устанавливается вместе с питоном)

## Клонирование репозитория

Для клонирования репозитория на свой компьютер воспользуйтесь следующей командой:

```bash
git clone https://github.com/Mirvitik/site-launcher-for-edu
```

## Установка

**Создание виртуального окружения**

Linux/MacOS

```bash
python3 -m venv venv
```

Windows

```bash
python -m venv venv
```

Активировать среду на Linux/MacOS

```bash
source venv/bin/activate
```

Или на Windows

```bash
venv\Scripts\activate
```

Перейдите в папку с проектом

```bash
cd site-launcher-for-edu
```

Установите зависимости

```bash
pip install -r requirements.txt
```

Linux/MacOS

```bash
python3 main.py
```

Windows

```bash
python main.py
```

Также приложение можно закомпилировать с помощью отдельной библиотеки PyInstaller

```bash
pyinstaller --onefile --noconsole main.py
```

Компиляция производится отдельно по желанию пользователя
