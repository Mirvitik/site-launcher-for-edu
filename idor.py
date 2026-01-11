import sys

from data import db_session
from flask import Flask, render_template, jsonify
import sqlite3

from data.users import User

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    con = sqlite3.connect("db/data.db")
    cur = con.cursor()
    query = """SELECT * FROM users"""
    users = cur.execute(query).fetchall()
    con.close()
    return render_template("idor.html", users=users)


@app.route("/user/<int:id>", methods=["GET"])
def get_user(id):
    con = sqlite3.connect("db/data.db")
    cur = con.cursor()
    query = """SELECT * FROM users WHERE users.id = ?"""
    user = cur.execute(query, (id,)).fetchone()
    con.close()
    return render_template(
        "idor_user.html", id=user[0], username=user[1], about=user[3], email=user[2]
    )


@app.route("/api/user/<id>")
def api_user(id):
    con = sqlite3.connect("db/data.db")
    cur = con.cursor()
    query = """SELECT * FROM users WHERE users.id = ?"""
    user = cur.execute(query, (id,)).fetchone()
    con.close()
    return jsonify(user)


if __name__ == "__main__":
    db_session.global_init("db/data.db")
    con = sqlite3.connect("db/data.db")
    cur = con.cursor()
    if cur.execute('''SELECT * FROM users WHERE name="testuser"''').fetchone() is None:
        user = User(name="testuser", hashed_password="testuser")
        db_sess = db_session.create_session()
        db_sess.add(user)
        db_sess.commit()
        db_sess.close()
    if cur.execute('''SELECT * FROM users WHERE name="testuser2"''').fetchone() is None:
        user = User(name="testuser2", hashed_password="testuser2")
        db_sess = db_session.create_session()
        db_sess.add(user)
        db_sess.commit()
        db_sess.close()
    con.close()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    app.run(port=port)
