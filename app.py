import re
import sqlite3
import uuid
import html
from db import get_db
from functools import wraps
from flask import Flask, render_template, g, request, redirect, url_for, session, abort
from flask_sslify import SSLify
from flask_session import Session  #server-side session storage
from passlib.hash import pbkdf2_sha256

app = Flask(__name__)
app.config.from_pyfile('config.cfg', silent=True)

Session(app)
SSLify(app)

if not app.debug:
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = 10 * 60  #ten minutes


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'id' not in session:
            abort(401)
        return f(*args, **kwargs)

    return wrapper


@app.route("/")
def index():
    if 'id' in session:
        id = session['id']
        db = get_db()
        my_notes = db.execute("SELECT * FROM notes WHERE owner=?",
                              (id, )).fetchall()

        other_notes = db.execute(
            "SELECT * FROM notes_permissions INNER JOIN notes n ON note_id=n.id  WHERE user_id=?",
            (id, )).fetchall()
        return render_template(
            'index.html', my_notes=my_notes, other_notes=other_notes)
    return render_template('index.html')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if 'id' in session:
        return redirect(url_for("index"))
    if request.method == 'POST':
        email = request.form.get('email', None)
        password = request.form.get('password', None)
        if not email or not password:
            return render_template('login.html', error="Fill all inputs.")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=?",
                          (email, )).fetchone()
        if not user:
            return render_template(
                'login.html', error="Wrong user or password.")
        if pbkdf2_sha256.verify(password, user['password']):
            session['email'] = user['email']
            session['id'] = user['id']
            return redirect(url_for("index"))
        else:
            #honesty its just a wrong pass but lets keep it secret
            return render_template(
                'login.html', error="Wrong user or password.")
    return render_template('login.html')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if 'id' in session:
        return redirect(url_for("index"))
    if request.method == 'POST':
        email = request.form.get('email', None)
        password1 = request.form.get('password1', None)
        password2 = request.form.get('password2', None)

        if not email or not password1 or not password2:
            return render_template('register.html', error="Fill all inputs.")
        is_valid = re.search(
            r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email)

        if not is_valid:
            return render_template(
                'register.html', error="Email is incorrect.")

        if password1 != password2:
            return render_template(
                'register.html', error="Passwords does not match.")
        # generate new salt, and hash a password
        hash = pbkdf2_sha256.hash(password1)

        db = get_db()
        try:
            db.execute("INSERT INTO users (email,password) VALUES (?,?)",
                       (email, hash))
        except sqlite3.IntegrityError:
            return render_template(
                'register.html', error="Email is already taken.")
        db.commit()
        return redirect(url_for("login"))

    return render_template('register.html')


@app.route("/logout")
@login_required
def logout():
    session.pop('email', None)
    session.pop('id', None)
    return redirect(url_for("index"))


@app.route("/change-password", methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        oldpassword = request.form.get('oldpassword', None)
        password1 = request.form.get('password1', None)
        password2 = request.form.get('password2', None)
        if not oldpassword or not password1 or not password2:
            return render_template(
                'change_password.html', error="Fill all inputs.")
        if password1 != password2:
            return render_template(
                'change_password.html', error="Passwords does not match.")
        id = session['id']
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (id, )).fetchone()
        if user:
            if pbkdf2_sha256.verify(oldpassword, user['password']):
                hash = pbkdf2_sha256.hash(password1)
                db.execute("UPDATE users SET password=? WHERE id = ?",
                           (hash, user['id']))
                db.commit()
                return redirect(url_for("index"))
            else:
                #wrong pass lets better destroy session
                session.pop('email', None)
                session.pop('id', None)
                return redirect(url_for("index"))
        else:
            abort(500)
    return render_template('change_password.html')


@app.route("/note", methods=['GET', 'POST'])
@login_required
def add_note():
    """Add a new note"""
    if request.method == 'POST':
        note = request.form.get('note', None)
        public = bool(request.form.get('public', False))

        if note:
            note = html.escape(note)
            db = get_db()
            id = session['id']
            uid = str(uuid.uuid4())
            db.execute(
                "INSERT INTO notes (uuid,content,public,owner) VALUES (?,?,?,?)",
                (uid, note, int(public), id))
            db.commit()
            return redirect(url_for("index"))
        else:
            return render_template(
                'add_note.html', error="Note cannot be empty!")

    return render_template('add_note.html')


@app.route("/note/<uuid:note_uuid>", methods=['GET', 'POST'])
def view_note(note_uuid):
    """View or change note attributes"""
    db = get_db()
    note = db.execute(
        "SELECT * FROM notes INNER JOIN users u ON owner=u.id WHERE uuid=?",
        (str(note_uuid), )).fetchone()
    is_owner = False
    if 'id' in session and session['id'] == note['owner']:
        is_owner = True
    return render_template('note.html', note=note, is_owner=is_owner)
