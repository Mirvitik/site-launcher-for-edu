import sys

from data import db_session
from data.users import User
from flask import Flask, render_template, request
import sqlite3

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == "POST":
        login = request.form.get('login')
        password = request.form.get('password')
        con = sqlite3.connect('db/data.db')
        cur = con.cursor()

        # admin' OR '1'='1' --
        query = f"SELECT * FROM users WHERE name = '{login}' AND hashed_password = '{password}'"

        try:
            cur.execute(query)
            user = cur.fetchone()

            if user:
                return f"Добро пожаловать, {user[1]}!"
            else:
                return "Неверные логин или пароль"
        except Exception as e:
            return f"Ошибка: {str(e)}"
        finally:
            con.close()

    return render_template('login.html')


if __name__ == '__main__':
    db_session.global_init("db/data.db")
    con = sqlite3.connect('db/data.db')
    cur = con.cursor()
    if cur.execute('''SELECT * FROM users WHERE name="admin"''').fetchone() is None:
        user = User(name="admin", hashed_password="admin")
        db_sess = db_session.create_session()
        db_sess.add(user)
        db_sess.commit()
        db_sess.close()
    con.close()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    app.run(port=port)
