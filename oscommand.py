from subprocess import Popen
from flask import Flask, request, render_template_string

app = Flask(__name__)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Ping Utility</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="container mt-5">
    <div class="card">
        <div class="card-header">
            <h2>🔧 System Ping Utility</h2>
        </div>
        <div class="card-body">
            <form method="POST">
                <div class="mb-3">
                    <label class="form-label">Enter IP or hostname to ping:</label>
                    <input type="text" name="host" class="form-control" 
                           placeholder="example.com or 8.8.8.8" 
                           value="{{ request.form.host if request.form.host else '' }}">
                </div>
                <button type="submit" class="btn btn-primary">Ping</button>
            </form>

            {% if result %}
            <hr>
            <h5>Results:</h5>
            <div class="alert alert-info">
                <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px;">{{ result }}</pre>
            </div>
            {% endif %}
        </div>
    </div>
</body>
</html>
'''


def safe_ping(hostname, count=4):
    """Безопасное выполнение ping с учетом ОС"""

    # Определяем ОС
    system = platform.system().lower()

    try:
        if system == "windows":
            # Для Windows
            command = ["ping", "-n", str(count), hostname]
        else:
            # Для Linux/Mac
            command = ["ping", "-c", str(count), hostname]

        # Выполняем команду
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False
        )

        return result.stdout if result.returncode == 0 else result.stderr

    except Exception as e:
        return f"Error: {str(e)}"


@app.route('/', methods=['GET', 'POST'])
def index():
    # ... остальной код остается прежним ...

    if request.method == 'POST':
        host = request.form.get('host', '').strip()

        if host:
            try:
                # ✅ Используем безопасную функцию
                output = safe_ping(host, count=4)
                result = output
            except Exception as e:
                error = f"Error: {str(e)}"


if __name__ == '__main__':
    app.run(debug=True)