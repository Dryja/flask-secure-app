import re
import uuid
import math
import string
from functools import wraps
from flask import session
from passlib.hash import pbkdf2_sha256


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'id' not in session:
            return "", 401
        return f(*args, **kwargs)

    return wrapper


def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = str(uuid.uuid4())
    return session['_csrf_token']


def check_email(email):
    return re.search(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",
                     email)


def ent(pas):
    alph = []
    alph.append("abcdefghijklmnopqrstuvwxyz")  # 26
    alph.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")  # 26
    alph.append("0123456789")  # 10
    alph.append("!@#$%^&*()`~-_=+[{]}\\|;:'\",<.>/?")  # 32
    alph.append(" ")  # 1
    alphabets = [False] * len(alph)

    n = 0

    for c in pas:
        for i, charset in enumerate(alph):
            if c in charset:
                if not alphabets[i]:
                    n = n + len(charset)
                alphabets[i] = True
    return len(pas) * math.log2(n)


class WeakPassword(ValueError):
    pass


def pass_to_hash(password):
    """   
        A password is considered strong if:
        8 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
        Password entropy > 60
    """
    errors = []
    pass_ent = ent(password)
    if pass_ent < 60:
        errors.append(
            "Password entropy needs to be bigger than 60. Current entropy {}.".
            format(round(pass_ent, 2)))

    if len(password) < 8:
        errors.append("Password needs to be longer than 8.")

    if re.search(r"\d", password) is None:
        errors.append("Password needs 1 digit or more.")

    if re.search(r"[A-Z]", password) is None:
        errors.append("Password needs 1 uppercase letter or more.")

    if re.search(r"[a-z]", password) is None:
        errors.append("Password needs 1 lowercase letter or more.")

    if re.search(r"[\W]", password) is None:
        errors.append("Password needs 1 symbol or more.")

    if len(errors) > 0:
        raise WeakPassword(' '.join(errors))

    return pbkdf2_sha256.hash(password, rounds=50000)
