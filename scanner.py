import re
from pathlib import Path


class FlaskVulnerabilityScanner:
    def __init__(self, project_path):
        self.project_path = Path(project_path)
        self.results = {
            "sql_injection": [],
            "os_command_injection": [],
            "path_traversal": [],
            "other": [],
            "idor": [],
        }

    def scan(self):
        for py_file in self.project_path.rglob("*.py"):
            self._scan_file(py_file)
        return self.results

    def _scan_file(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                lines = content.split("\n")
            self._check_sql_injection(content, lines, filepath)
            self._check_path_traversal(content, lines, filepath)
            self._check_os_command_injection(content, lines, filepath)
            self._check_idor_vulnerability(content, lines, filepath)
            self._check_other_vulnerabilities(content, lines, filepath)

        except Exception as e:
            print(f"Ошибка при чтении {filepath}: {e}")

    def _check_sql_injection(self, content, lines, filepath):
        patterns = [
            (r'execute\s*\(\s*f["\']', "F-string в execute()"),
            (r'execute\s*\(\s*["\'].*?%s', "Форматирование %s в execute()"),
            (r'execute\s*\(\s*["\'].*?\+', "Конкатенация в execute()"),
            (r'cursor\.execute\s*\(\s*f["\']', "F-string в cursor.execute()"),
            (r'query\s*=\s*f["\'].*?\{.*?\}', "F-string в SQL запросе"),
            (r'query\s*=\s*["\'].*?%s.*?%', "Форматирование %s в SQL запросе"),
            (r'query\s*=\s*["\'].*?\+.*?\+', "Конкатенация в SQL запросе"),
            (r'query\s*=\s*["\'].*?\.format\(', ".format() в SQL запросе"),
            (r"raw\s+sql", "Raw SQL запрос"),
            (r'sqlalchemy\.text\s*\(\s*f["\']', "F-string в SQLAlchemy text()"),
            (r'text\s*\(\s*f["\']', "F-string в text()"),
            (r"\$\$\s*.*?\s*\$\$.*?request\.", "Шаблон с request в SQL"),
            (r'["\'].*?WHERE.*?=.*?["\']\s*\+\s*', "Конкатенация в WHERE условии"),
            (r'["\'].*?WHERE.*?=.*?f["\'].*?\{', "F-string в WHERE условии"),
        ]
        sql_keywords = [
            "select",
            "insert",
            "update",
            "delete",
            "create",
            "drop",
            "alter",
            "execute",
            "cursor.execute",
            "raw",
            "query",
        ]
        user_input_sources = [
            "request",
            "form",
            "args",
            "json",
            "get_json",
            "cookies",
            "headers",
            "values",
            "get",
        ]

        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            has_sql_keyword = any(keyword in line_lower for keyword in sql_keywords)
            has_user_input = any(source in line_lower for source in user_input_sources)

            has_dynamic_construction = any(
                [
                    "+" in line and "query" in line_lower,
                    "%" in line and "query" in line_lower,
                    ".format(" in line
                    and ("query" in line_lower or "sql" in line_lower),
                    'f"' in line and ("query" in line_lower or "sql" in line_lower),
                    "f'" in line and ("query" in line_lower or "sql" in line_lower),
                    "f-string" in line_lower,
                ]
            )
            if has_sql_keyword and has_user_input and has_dynamic_construction:
                self.results["sql_injection"].append(
                    {
                        "file": str(filepath),
                        "line": line_num,
                        "code": line.strip(),
                        "description": "Прямая подстановка пользовательского ввода в SQL запрос",
                        "risk": "HIGH",
                    }
                )
                continue
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    if has_user_input:
                        self.results["sql_injection"].append(
                            {
                                "file": str(filepath),
                                "line": line_num,
                                "code": line.strip(),
                                "description": desc,
                                "risk": "HIGH",
                            }
                        )
                    elif has_dynamic_construction and has_sql_keyword:
                        self.results["sql_injection"].append(
                            {
                                "file": str(filepath),
                                "line": line_num,
                                "code": line.strip(),
                                "description": f"{desc} (возможно через переменные)",
                                "risk": "MEDIUM",
                            }
                        )

            if "query" in line_lower and "=" in line and has_dynamic_construction:
                if has_user_input or any(
                    var in line
                    for var in ["login", "password", "username", "email", "id"]
                ):
                    self.results["sql_injection"].append(
                        {
                            "file": str(filepath),
                            "line": line_num,
                            "code": line.strip(),
                            "description": "Динамическое построение SQL запроса с переменными",
                            "risk": "HIGH",
                        }
                    )

    def _check_os_command_injection(self, content, lines, filepath):
        command_indicators = [
            "command =",
            "cmd =",
            "system_command =",
            "ping_command =",
        ]
        dangerous_funcs = [
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_output",
            "os.system",
            "os.popen",
        ]

        user_input_sources = [
            "request.args.get",
            "request.form.get",
            "request.values.get",
            "request.get_json",
            "request.cookies.get",
            "request.headers.get",
        ]

        injection_patterns = [
            (
                r'command\s*=\s*["\'].*?[\'"]\s*\+\s*\w+',
                "Конкатенация при построении команды",
            ),
            (
                r'command\s*=\s*["\'].*?\{\}.*?\.format',
                "format() при построении команды",
            ),
            (r'command\s*=\s*f["\'].*?\{.*?\}', "F-string при построении команды"),
            (
                r"ping.*?\+.*?(host|ip|address)",
                "Динамическая подстановка в ping команду",
            ),
            (r'["\']ping["\'].*?\+\s*(host|ip)', "Конкатенация в ping команде"),
            (
                r"subprocess\.(run|Popen|call).*?shell\s*=\s*True",
                "subprocess с shell=True",
            ),
            (
                r"subprocess\.(run|Popen|call)\(\s*command\s*,",
                "Выполнение динамической команды",
            ),
            (r"host\s*=\s*request\.args\.get", "Получение host из параметров URL"),
            (r'redirect\(f"/\?host=\{host\}"', "Передача host через redirect"),
        ]

        dangerous_chars = [";", "&", "|", "$", "`", ">", "<", "\n", "\r", "\t"]

        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            line_stripped = line.strip()

            if "host =" in line_lower and (
                "request.args.get" in line_lower or "request.form.get" in line_lower
            ):
                self.results["os_command_injection"].append(
                    {
                        "file": str(filepath),
                        "line": line_num,
                        "code": line.strip(),
                        "description": "Получение host из пользовательского ввода",
                        "risk": "INFO",
                    }
                )
            if any(indicator in line_lower for indicator in command_indicators):
                if "host" in line_lower or any(
                    op in line for op in ["+", 'f"', "f'", ".format"]
                ):
                    self.results["os_command_injection"].append(
                        {
                            "file": str(filepath),
                            "line": line_num,
                            "code": line.strip(),
                            "description": "Динамическое построение системной команды с использованием переменных",
                            "risk": "HIGH",
                        }
                    )
            if "ping" in line_lower and (
                "command" in line_lower or "cmd" in line_lower
            ):
                if "host" in line_lower or any(op in line for op in ["+", 'f"', "f'"]):
                    self.results["os_command_injection"].append(
                        {
                            "file": str(filepath),
                            "line": line_num,
                            "code": line.strip(),
                            "description": "Динамическое построение ping команды с подстановкой host",
                            "risk": "CRITICAL",
                        }
                    )
            for func in dangerous_funcs:
                if func in line_lower and "shell=true" in line_lower:
                    risk = "CRITICAL"
                    desc = f"{func} с shell=True - прямая командая инъекция"

                    if "command" in line_lower or "cmd" in line_lower:
                        desc += " с динамической командой"

                    self.results["os_command_injection"].append(
                        {
                            "file": str(filepath),
                            "line": line_num,
                            "code": line.strip(),
                            "description": desc,
                            "risk": risk,
                        }
                    )
            for pattern, desc in injection_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.results["os_command_injection"].append(
                        {
                            "file": str(filepath),
                            "line": line_num,
                            "code": line.strip(),
                            "description": desc,
                            "risk": "HIGH",
                        }
                    )
            if "host" in line_lower and any(
                source in line_lower for source in ["request", "get"]
            ):
                for char in dangerous_chars:
                    if char in line:
                        self.results["os_command_injection"].append(
                            {
                                "file": str(filepath),
                                "line": line_num,
                                "code": line.strip(),
                                "description": f"Пользовательский ввод может содержать опасный символ '{char}'",
                                "risk": "HIGH",
                            }
                        )
            if (
                "command =" in line
                and '".join(' in line
                and ("ping" in line or "host" in line)
            ):
                if "host" in line:
                    self.results["os_command_injection"].append(
                        {
                            "file": str(filepath),
                            "line": line_num,
                            "code": line.strip(),
                            "description": "OS Command Injection: host подставляется напрямую в команду ping",
                            "risk": "CRITICAL",
                        }
                    )
            if "host" in line and ("command" in line_lower or "ping" in line_lower):
                if line_stripped and not line_stripped.startswith("#"):
                    if not any(
                        secure in line_lower
                        for secure in ["shlex.quote", "escape", "sanitize"]
                    ):
                        self.results["os_command_injection"].append(
                            {
                                "file": str(filepath),
                                "line": line_num,
                                "code": line.strip(),
                                "description": "Прямая подстановка переменной host в системную команду",
                                "risk": "CRITICAL",
                            }
                        )
        full_content_lower = content.lower()
        if (
            "request.args.get" in full_content_lower
            and "subprocess.run" in full_content_lower
        ):
            if "shell=true" in full_content_lower and (
                "command =" in content or "ping" in full_content_lower
            ):
                if not any(
                    item["description"]
                    == "Цепочка OS Command Injection: пользовательский ввод → динамическая команда → subprocess с shell=True"
                    for item in self.results["os_command_injection"]
                ):
                    self.results["os_command_injection"].append(
                        {
                            "file": str(filepath),
                            "line": 1,
                            "code": "Весь файл",
                            "description": "Цепочка OS Command Injection: пользовательский ввод → динамическая команда → subprocess с shell=True",
                            "risk": "CRITICAL",
                        }
                    )

    def _check_path_traversal(self, content, lines, filepath):
        traversal_patterns = [
            (r"send_file\s*\(\s*filename", "send_file() с параметром filename"),
            (r"send_file\s*\(\s*request\.", "send_file() с пользовательским вводом"),
            (
                r"send_file\s*\(\s*\w+\s*,\s*as_attachment",
                "send_file() с динамическим именем файла",
            ),
            (r"return\s+send_file\s*\(", "Возврат файла через send_file"),
            (
                r"send_from_directory\s*\(.*?request\.",
                "send_from_directory() с пользовательским вводом",
            ),
            (
                r"send_from_directory\s*\(.*?filename",
                "send_from_directory() с параметром filename",
            ),
            (r"open\s*\(\s*request\.", "open() с пользовательским вводом"),
            (
                r'open\s*\(\s*\w+\s*,\s*["\']r["\']',
                "open() с динамическим именем файла",
            ),
            (r"os\.path\.join.*?request\.", "os.path.join() с пользовательским вводом"),
            (r"path\.join.*?request\.", "path.join() с пользовательским вводом"),
            (r"os\.listdir.*?request\.", "os.listdir() с пользовательским вводом"),
            (r"os\.remove.*?request\.", "os.remove() с пользовательским вводом"),
            (r"shutil\.copy.*?request\.", "shutil.copy() с пользовательским вводом"),
            (r"\.\./", "Обнаружен паттерн path traversal (../)"),
            (r"\.\.\\\\", "Обнаружен паттерн path traversal (..\\)"),
            (r"%2e%2e%2f", "URL-encoded path traversal (%2e%2e%2f)"),
            (r"%2e%2e\\\\", "URL-encoded path traversal (%2e%2e\\)"),
            (
                r"filename\s*=\s*request\.args\.get",
                "Получение имени файла из параметров URL",
            ),
            (r"filename\s*=\s*request\.form\.get", "Получение имени файла из формы"),
            (
                r"file\s*=\s*request\.args\.get",
                "Получение пути к файлу из параметров URL",
            ),
            (
                r"filepath\s*=\s*request\.args\.get",
                "Получение пути к файлу из параметров URL",
            ),
        ]
        safe_patterns = [
            "normpath",
            "abspath",
            "safe_join",
            "os.path.basename",
            "secure_filename",
            "werkzeug.utils.secure_filename",
            "validate_filename",
            "sanitize_filename",
            "os.path.realpath",
        ]

        user_input_vars = ["filename", "file", "path", "name", "filepath", "file_name"]
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            line_stripped = line.strip()
            if re.search(
                r'filename\s*=\s*request\.args\.get\s*\(\s*["\']file["\']\s*\)', line
            ):
                self.results["path_traversal"].append(
                    {
                        "file": str(filepath),
                        "line": line_num,
                        "code": line.strip(),
                        "description": "Path Traversal: получение пути к файлу из параметра 'file' URL без валидации",
                        "risk": "CRITICAL",
                    }
                )

            if re.search(r"return\s+send_file\s*\(\s*filename\s*,", line):
                has_validation = False
                for prev_line in lines[max(0, line_num - 10) : line_num]:
                    prev_lower = prev_line.lower()
                    if any(safe in prev_lower for safe in safe_patterns):
                        has_validation = True
                        break
                    if "if" in prev_lower and (
                        "filename" in prev_lower or "file" in prev_lower
                    ):
                        if "endswith" in prev_lower or "split" in prev_lower:
                            has_validation = True
                            break

                if not has_validation:
                    self.results["path_traversal"].append(
                        {
                            "file": str(filepath),
                            "line": line_num,
                            "code": line.strip(),
                            "description": "Path Traversal: send_file возвращает произвольный файл без проверки пути",
                            "risk": "CRITICAL",
                        }
                    )

            if "send_file" in line:
                if "request.args.get" in line_lower or "request.form.get" in line_lower:
                    self.results["path_traversal"].append(
                        {
                            "file": str(filepath),
                            "line": line_num,
                            "code": line.strip(),
                            "description": "send_file() использует имя файла из пользовательского ввода без проверки",
                            "risk": "CRITICAL",
                        }
                    )
                elif any(var in line for var in user_input_vars):
                    for prev_line in lines[max(0, line_num - 10) : line_num]:
                        if (
                            "request.args.get" in prev_line
                            or "request.form.get" in prev_line
                        ):
                            self.results["path_traversal"].append(
                                {
                                    "file": str(filepath),
                                    "line": line_num,
                                    "code": line.strip(),
                                    "description": f"send_file() использует переменную, полученную от пользователя",
                                    "risk": "CRITICAL",
                                }
                            )
                            break

            if re.search(
                r"(filename|file|path|filepath)\s*=\s*request\.(args|form)\.get", line
            ):
                has_validation = any(safe in line_lower for safe in safe_patterns)

                if not has_validation:
                    var_match = re.search(
                        r"(filename|file|path|filepath)\s*=", line_lower
                    )
                    var_name = var_match.group(1) if var_match else "filename"

                    self.results["path_traversal"].append(
                        {
                            "file": str(filepath),
                            "line": line_num,
                            "code": line.strip(),
                            "description": f"Получение {var_name} из пользовательского ввода без валидации",
                            "risk": "HIGH",
                        }
                    )

                    var_pattern = r"\b" + re.escape(var_name) + r"\b"
                    for next_line in lines[
                        line_num + 1 : min(line_num + 15, len(lines))
                    ]:
                        if (
                            re.search(var_pattern, next_line, re.IGNORECASE)
                            and "send_file" in next_line
                        ):
                            self.results["path_traversal"].append(
                                {
                                    "file": str(filepath),
                                    "line": line_num + 1,
                                    "code": next_line.strip(),
                                    "description": f"Переменная {var_name} используется в send_file без проверки пути",
                                    "risk": "CRITICAL",
                                }
                            )
                            break

            for pattern, desc in traversal_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    has_safe_func = any(safe in line_lower for safe in safe_patterns)

                    has_validation = False
                    for prev_line in lines[max(0, line_num - 10) : line_num]:
                        if any(safe in prev_line.lower() for safe in safe_patterns):
                            has_validation = True
                            break

                    if not has_safe_func and not has_validation:
                        risk = (
                            "CRITICAL"
                            if "send_file" in pattern or "open" in pattern
                            else "HIGH"
                        )
                        self.results["path_traversal"].append(
                            {
                                "file": str(filepath),
                                "line": line_num,
                                "code": line.strip(),
                                "description": desc,
                                "risk": risk,
                            }
                        )

            if "filename" in line_lower and (
                ".." in line or "./" in line or "~/" in line
            ):
                self.results["path_traversal"].append(
                    {
                        "file": str(filepath),
                        "line": line_num,
                        "code": line.strip(),
                        "description": "Обнаружены символы path traversal (..) в имени файла",
                        "risk": "HIGH",
                    }
                )

            if "return send_file" in line and not any(
                safe in line_lower for safe in safe_patterns
            ):
                var_match = re.search(r"send_file\s*\(\s*(\w+)", line)
                if var_match:
                    var_name = var_match.group(1)
                    for prev_line in lines[max(0, line_num - 15) : line_num]:
                        if (
                            f"{var_name} = request." in prev_line
                            or f"{var_name}=" in prev_line
                            and "request." in prev_line
                        ):
                            self.results["path_traversal"].append(
                                {
                                    "file": str(filepath),
                                    "line": line_num,
                                    "code": line.strip(),
                                    "description": f"Path Traversal: переменная '{var_name}' получена от пользователя и используется в send_file без проверки",
                                    "risk": "CRITICAL",
                                }
                            )
                            break
        full_content_lower = content.lower()

        if (
            "request.args.get" in full_content_lower
            and "send_file" in full_content_lower
        ):
            if any(
                var in full_content_lower for var in ["filename", "filepath", "file"]
            ):
                has_secure = any(safe in full_content_lower for safe in safe_patterns)

                if not has_secure:
                    already_added = False
                    for item in self.results["path_traversal"]:
                        if (
                            item.get("description")
                            == "Общая уязвимость Path Traversal: цепочка получения файла из пользовательского ввода без валидации"
                        ):
                            already_added = True
                            break

                    if not already_added:
                        self.results["path_traversal"].append(
                            {
                                "file": str(filepath),
                                "line": 1,
                                "code": "Анализ всего файла",
                                "description": "Общая уязвимость Path Traversal: цепочка получения файла из пользовательского ввода без валидации",
                                "risk": "CRITICAL",
                            }
                        )

        if "send_file" in full_content_lower and not any(
            word in full_content_lower for word in safe_patterns
        ):
            already_added = False
            for item in self.results["path_traversal"]:
                if (
                    item.get("description")
                    == "Отсутствует нормализация пути при передаче файлов. Возможно чтение любых файлов системы"
                ):
                    already_added = True
                    break

            if not already_added:
                self.results["path_traversal"].append(
                    {
                        "file": str(filepath),
                        "line": 1,
                        "code": "Общая уязвимость",
                        "description": "Отсутствует нормализация пути при передаче файлов. Возможно чтение любых файлов системы",
                        "risk": "CRITICAL",
                    }
                )

    def _check_other_vulnerabilities(self, content, lines, filepath):
        for line_num, line in enumerate(lines, 1):
            if "render_template_string" in line and "request" in line.lower():
                self.results["other"].append(
                    {
                        "file": str(filepath),
                        "line": line_num,
                        "code": line.strip(),
                        "description": "Потенциальная SSTI в render_template_string",
                        "risk": "HIGH",
                    }
                )

            if "eval(" in line and "request" in line.lower():
                self.results["other"].append(
                    {
                        "file": str(filepath),
                        "line": line_num,
                        "code": line.strip(),
                        "description": "eval() с пользовательским вводом",
                        "risk": "HIGH",
                    }
                )

            if "pickle.loads" in line and "request" in line.lower():
                self.results["other"].append(
                    {
                        "file": str(filepath),
                        "line": line_num,
                        "code": line.strip(),
                        "description": "Pickle deserialization с пользовательскими данными",
                        "risk": "HIGH",
                    }
                )

    def _check_idor_vulnerability(self, content, lines, filepath):
        idor_patterns = [
            (r"@app\.route\(.*?/<int:id>", "IDOR: параметр id в маршруте (int)"),
            (r"@app\.route\(.*?/<id>", "IDOR: параметр id в маршруте"),
            (r"@app\.route\(.*?/<user_id>", "IDOR: параметр user_id в маршруте"),
            (
                r"@app\.route\(.*?/<int:user_id>",
                "IDOR: параметр user_id в маршруте (int)",
            ),
            (
                r'request\.args\.get\(["\']id["\']',
                "IDOR: получение id из параметров URL",
            ),
            (
                r'request\.args\.get\(["\']user_id["\']',
                "IDOR: получение user_id из параметров URL",
            ),
            (r'request\.form\.get\(["\']id["\']', "IDOR: получение id из формы"),
            (
                r'request\.get_json\(.*?\)\.get\(["\']id["\']',
                "IDOR: получение id из JSON",
            ),
            (r"WHERE.*?id\s*=\s*\?.*?\(id,\)", "IDOR: использование id в SQL запросе"),
            (
                r"WHERE.*?user_id\s*=\s*\?.*?\(user_id,\)",
                "IDOR: использование user_id в SQL запросе",
            ),
            (r"WHERE.*?id\s*=\s*\{\}", "IDOR: подстановка id в SQL запрос"),
            (r"@app\.route\(.*?/api/.*?/<id>", "IDOR: API эндпоинт с параметром id"),
            (
                r"@app\.route\(.*?/api/.*?/<int:id>",
                "IDOR: API эндпоинт с параметром id (int)",
            ),
            (r"def\s+\w+\(.*?id.*?\):", "Функция принимает id параметр"),
            (
                r"def\s+\w+\(.*?id.*?\).*?@app\.route",
                "Отсутствует проверка авторизации для доступа по id",
            ),
        ]
        auth_indicators = [
            "login_required",
            "auth_required",
            "current_user",
            "session",
            "g.user",
            "request.authorization",
            "flask_login",
            "login_user",
            "logout_user",
            "UserMixin",
            "login_manager",
            "requires_roles",
            "permission_required",
            "has_role",
            "has_permission",
            "admin_required",
        ]
        access_checks = [
            "if current_user.id",
            "if user.id",
            "if id == session",
            "if id == current_user",
            "check_permission",
            "has_access",
            "if user.role",
            "if user.is_admin",
            "user.id ==",
            "can_access",
        ]
        routes = []
        current_function = None
        function_lines = {}
        for line_num, line in enumerate(lines, 1):
            route_match = re.search(r'@app\.route\(["\']([^"\']+)["\']', line)
            if route_match:
                route_path = route_match.group(1)
                for next_line_num in range(line_num, min(line_num + 5, len(lines))):
                    func_match = re.search(r"def\s+(\w+)\(", lines[next_line_num - 1])
                    if func_match:
                        function_name = func_match.group(1)
                        routes.append(
                            {
                                "line": line_num,
                                "path": route_path,
                                "function": function_name,
                                "function_line": next_line_num,
                            }
                        )
                        break

        for route in routes:
            function_line = route["function_line"]
            function_name = route["function"]
            has_id_param = False
            id_param_name = None
            for line_num in range(
                function_line - 1, min(function_line + 1, len(lines))
            ):
                if line_num < len(lines):
                    id_match = re.search(r"def\s+\w+\((.*?)\)", lines[line_num])
                    if id_match:
                        params = id_match.group(1)
                        if re.search(r"\bid\b", params):
                            has_id_param = True
                            id_param_name = "id"
                        elif re.search(r"\buser_id\b", params):
                            has_id_param = True
                            id_param_name = "user_id"
            has_auth = False
            has_access_check = False
            end_line = len(lines)
            for next_route in routes:
                if next_route["function_line"] > function_line:
                    end_line = next_route["function_line"]
                    break

            for line_num in range(function_line, min(end_line + 20, len(lines))):
                if line_num >= len(lines):
                    break
                line_content = lines[line_num]
                line_lower = line_content.lower()
                if any(indicator in line_lower for indicator in auth_indicators):
                    has_auth = True
                if any(check in line_lower for check in access_checks):
                    has_access_check = True
                if id_param_name and f"{id_param_name} ==" in line_lower:
                    has_access_check = True
                if id_param_name and f"{id_param_name} !=" in line_lower:
                    has_access_check = True
            if has_id_param and (not has_auth or not has_access_check):
                self.results["idor"].append(
                    {
                        "file": str(filepath),
                        "line": route["line"],
                        "code": lines[route["line"] - 1].strip(),
                        "description": f"IDOR: эндпоинт '{route['path']}' принимает ID параметр '{id_param_name}' без проверки прав доступа",
                        "risk": "CRITICAL",
                        "function": function_name,
                        "id_param": id_param_name,
                    }
                )
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            for pattern, desc in idor_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    has_auth_context = False
                    for check_line in lines[
                        max(0, line_num - 30) : min(len(lines), line_num + 10)
                    ]:
                        if any(
                            indicator in check_line.lower()
                            for indicator in auth_indicators
                        ):
                            has_auth_context = True
                            break

                    if not has_auth_context:
                        self.results["idor"].append(
                            {
                                "file": str(filepath),
                                "line": line_num,
                                "code": line.strip(),
                                "description": desc,
                                "risk": "HIGH",
                            }
                        )

            if "api" in line_lower and ("/<id>" in line or "/<int:id>" in line):
                has_api_auth = False
                for check_line in lines[
                    max(0, line_num - 20) : min(len(lines), line_num + 5)
                ]:
                    if any(
                        indicator in check_line.lower() for indicator in auth_indicators
                    ):
                        has_api_auth = True
                        break

                if not has_api_auth:
                    self.results["idor"].append(
                        {
                            "file": str(filepath),
                            "line": line_num,
                            "code": line.strip(),
                            "description": "IDOR: API эндпоинт без аутентификации позволяет получить данные по ID",
                            "risk": "CRITICAL",
                        }
                    )
            if "where" in line_lower and "id" in line_lower:
                has_user_input = False
                for prev_line in lines[max(0, line_num - 20) : line_num]:
                    if "request" in prev_line and (
                        "args.get" in prev_line or "form.get" in prev_line
                    ):
                        if "id" in prev_line:
                            has_user_input = True
                            break

                if has_user_input:
                    has_auth_check = False
                    for prev_line in lines[max(0, line_num - 30) : line_num]:
                        if any(check in prev_line.lower() for check in access_checks):
                            has_auth_check = True
                            break

                    if not has_auth_check:
                        self.results["idor"].append(
                            {
                                "file": str(filepath),
                                "line": line_num,
                                "code": line.strip(),
                                "description": "IDOR: прямой доступ к данным по ID без проверки прав пользователя",
                                "risk": "CRITICAL",
                            }
                        )

    def generate_report(self):
        report = []
        report.append("=" * 80)
        report.append("ОТЧЕТ ПО УЯЗВИМОСТЯМ FLASK ПРОЕКТА")
        report.append("=" * 80)

        total = 0
        risk_levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for vuln_type, findings in self.results.items():
            if findings:
                report.append(
                    f"\n[{vuln_type.upper()}] Найдено {len(findings)} потенциальных уязвимостей:"
                )
                for item in findings:
                    risk = item.get("risk", "MEDIUM")
                    risk_levels[risk] = risk_levels.get(risk, 0) + 1

                    risk_emoji = {
                        "CRITICAL": "💀",
                        "HIGH": "🔴",
                        "MEDIUM": "🟡",
                        "LOW": "🟢",
                        "INFO": "ℹ️",
                    }.get(risk, "⚪")

                    report.append(f"\n  {risk_emoji} Файл: {item['file']}")
                    report.append(f"  📍 Строка: {item['line']}")
                    report.append(f"  ⚠️  Описание: {item['description']}")
                    report.append(f"  🚨 Уровень риска: {risk}")
                    report.append(f"  💻 Код: {item['code'][:150]}")
                total += len(findings)
            else:
                report.append(f"\n[{vuln_type.upper()}] Уязвимостей не найдено")

        report.append("\n" + "=" * 80)
        report.append(f"ИТОГО: Найдено {total} потенциальных уязвимостей")
        if risk_levels["CRITICAL"] > 0:
            report.append(
                f"  💀 CRITICAL: {risk_levels['CRITICAL']} - ТРЕБУЕТ НЕМЕДЛЕННОГО ИСПРАВЛЕНИЯ!"
            )
        report.append(f"  🔴 HIGH: {risk_levels['HIGH']}")
        report.append(f"  🟡 MEDIUM: {risk_levels['MEDIUM']}")
        report.append(f"  🟢 LOW: {risk_levels['LOW']}")
        report.append("=" * 80)
        if risk_levels["CRITICAL"] > 0 or risk_levels["HIGH"] > 0:
            if self.results["path_traversal"]:
                report.append("\n🔧 РЕКОМЕНДАЦИИ ПО ИСПРАВЛЕНИЮ PATH TRAVERSAL:")
                report.append(
                    "1. Используйте os.path.normpath() для нормализации пути:"
                )
                report.append("   safe_path = os.path.normpath(filename)")
                report.append("")
                report.append(
                    "2. Проверяйте, что путь не выходит за пределы базовой директории:"
                )
                report.append("   base_dir = os.path.abspath('files/')")
                report.append(
                    "   requested_path = os.path.abspath(os.path.join(base_dir, filename))"
                )
                report.append("   if not requested_path.startswith(base_dir):")
                report.append("       abort(403)")
                report.append("")
                report.append("3. Используйте безопасные функции Flask:")
                report.append("   from flask import send_from_directory")
                report.append("   return send_from_directory('images/', filename)")
                report.append("")
                report.append("4. Валидируйте имена файлов:")
                report.append("   from werkzeug.utils import secure_filename")
                report.append("   safe_filename = secure_filename(filename)")
                report.append("")
                report.append("5. ПРИМЕР БЕЗОПАСНОГО КОДА ДЛЯ ВАШЕГО СЛУЧАЯ:")
                report.append("   @app.route('/download')")
                report.append("   def download_file():")
                report.append("       filename = request.args.get('file')")
                report.append("       if not filename:")
                report.append("           abort(400)")
                report.append("       safe_filename = secure_filename(filename)")
                report.append(
                    "       return send_from_directory('images/', safe_filename)"
                )

            if self.results["os_command_injection"]:
                report.append("\n🔧 РЕКОМЕНДАЦИИ ПО ИСПРАВЛЕНИЮ OS COMMAND INJECTION:")
                report.append("1. НЕ используйте shell=True в subprocess")
                report.append("2. Используйте список аргументов вместо строки команды:")
                report.append("   subprocess.run(['ping', '-c', '1', host])")
                report.append(
                    "3. Валидируйте host: разрешите только IP адреса или доменные имена"
                )
                report.append(
                    "4. Используйте shlex.quote() для экранирования спецсимволов"
                )

            if self.results["sql_injection"]:
                report.append("\n🔧 РЕКОМЕНДАЦИИ ПО ИСПРАВЛЕНИЮ SQL INJECTION:")
                report.append("1. Используйте параметризованные запросы")
                report.append("2. Применяйте ORM с безопасными методами")
                report.append("3. Валидируйте и экранируйте пользовательский ввод")

        return "\n".join(report)
