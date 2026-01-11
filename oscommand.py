import subprocess
import sys

from flask import Flask, request, render_template, redirect
import os

app = Flask(__name__)


# http://127.0.0.1:5000/?host=8.8.8.8%26cd
@app.route("/", methods=["GET", "POST"])
def unsafe_ping():
    if request.method == "POST":
        host = request.form.get("host")
        return redirect(f"/?host={host}")

    host = request.args.get("host", "127.0.0.1")

    if os.name == "nt":
        command = " ".join(["ping", "-n", "1", host])
    else:
        command = " ".join(["ping", "-c", "1", host])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            shell=True,
            encoding="cp866",
        )

        output = f"""
                <h3>Результат выполнения команды:</h3>
                <pre>Команда: {command}</pre>
                <h4>Вывод:</h4>
                <pre>{result.stdout if result.stdout else 'Нет вывода'}</pre>
                """

        if result.stderr:
            output += f"<h4>Ошибки:</h4><pre>{result.stderr}</pre>"

        output += f"<p>Код возврата: {result.returncode}</p>"

        return render_template(
            "oscommand.html",
            errors=result.stderr,
            code=result.returncode,
            command=command,
            res=result.stdout if result.stdout else "Нет вывода",
        )

    except subprocess.TimeoutExpired:
        return "Ошибка: команда превысила время выполнения (5 секунд)"
    except Exception as e:
        return f"Ошибка выполнения: {str(e)}"


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    app.run(port=port)
