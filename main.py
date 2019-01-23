import sqlite3
import uuid
import html
import time
from db import get_db
from helpers import login_required, generate_csrf_token, check_email, pass_to_hash, WeakPassword
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


#csrf protection
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(403)


app.jinja_env.globals['csrf_token'] = generate_csrf_token


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
        if not email or not password or not check_email(email):
            return render_template(
                'login.html', error="Fill all inputs, email may be incorrect.")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=?",
                          (email, )).fetchone()
        if not user:
            time.sleep(0.5)  #slow down
            return render_template(
                'login.html', error="Wrong user or password.")
        if pbkdf2_sha256.verify(password, user['password']):
            session['email'] = user['email']
            session['id'] = user['id']
            return redirect(url_for("index"))
        else:
            #honesty its just a wrong pass but lets keep it secret
            time.sleep(0.5)  #slow down
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
        is_valid = check_email(email)

        if not is_valid:
            return render_template(
                'register.html', error="Email is incorrect.")

        if password1 != password2:
            return render_template(
                'register.html', error="Passwords does not match.")
        # generate new salt, and hash a password
        try:
            hash = pass_to_hash(password1)
        except WeakPassword as e:
            return render_template(
                'register.html', error="Password is not secure. " + str(e))

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
                try:
                    hash = pass_to_hash(password1)
                except WeakPassword as e:
                    return render_template(
                        'change_password.html',
                        error="Password is not secure." + str(e))

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


@app.route("/note/<uuid:note_uuid>/", methods=['POST'])
@login_required
def note_permissions(note_uuid):
    """Edit note permissions"""
    action = request.form.get('action', None)
    email = request.form.get('user', None)
    if not email or not check_email(email):
        return "Wrong email", 400
    db = get_db()
    note = db.execute("SELECT id,owner FROM notes WHERE uuid=?",
                      (str(note_uuid), )).fetchone()
    user = db.execute("SELECT id FROM users WHERE email=?",
                      (email, )).fetchone()
    if note['owner'] != session['id']:
        return "You are not an owner", 403
    if not user:
        return "User not found", 400
    if action == "del":
        db.execute(
            "DELETE FROM notes_permissions WHERE user_id = ? AND note_id = ?",
            (user['id'], note['id']))
        db.commit()
        return redirect(url_for('view_note', note_uuid=note_uuid))
    elif action == "add":
        db.execute(
            "INSERT INTO notes_permissions (user_id,note_id) VALUES (?,?)",
            (user['id'], note['id']))
        db.commit()
        return redirect(url_for('view_note', note_uuid=note_uuid))
    abort(404)


@app.route("/note/<uuid:note_uuid>")
def view_note(note_uuid):
    """View or change note attributes"""
    db = get_db()
    note = db.execute(
        "SELECT n.id,n.uuid,n.content,n.owner,n.public,u.email FROM notes n INNER JOIN users u ON owner=u.id WHERE uuid=?",
        (str(note_uuid), )).fetchone()
    is_owner = False
    allowed = False
    shared = None
    if 'id' in session:
        if session['id'] == note['owner']:
            shared = db.execute(
                "SELECT * FROM notes_permissions INNER JOIN users u ON user_id=u.id WHERE note_id=?",
                (note['id'], )).fetchall()
            is_owner = True
        else:
            permission = db.execute(
                "SELECT id FROM notes_permissions WHERE user_id=? AND note_id=?",
                (session['id'], note['id'])).fetchone()
            allowed = permission
    if note['public'] or is_owner or allowed:
        return render_template(
            'note.html', note=note, is_owner=is_owner, shared=shared)
    else:
        return "Not found", 404
