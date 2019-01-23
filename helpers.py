import re
import uuid
import math
from collections import Counter
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


def ent(data):
    data = list(data)
    if len(data) <= 1:
        return 0

    counts = Counter()
    for d in data:
        counts[d] += 1
    ent = 0
    probs = [float(c) / len(data) for c in counts.values()]
    for p in probs:
        if p > 0.:
            ent -= p * math.log2(p)

    return ent


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
        Password entropy > 2
    """
    pass_ent = ent(password)
    if pass_ent < 2:
        raise WeakPassword(
            'Password entropy needs to be bigger than 2. Current entropy ' +
            str(pass_ent))
    if len(password) < 8:
        raise WeakPassword('Password needs to be longer than 8.')

    if re.search(r"\d", password) is None:
        raise WeakPassword('Password needs 1 digit or more.')

    if re.search(r"[A-Z]", password) is None:
        raise WeakPassword('Password needs 1 uppercase letter or more.')

    if re.search(r"[a-z]", password) is None:
        raise WeakPassword('Password needs 1 lowercase letter or more.')

    if re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~" + r'"]', password) is None:
        raise WeakPassword('Password needs 1 symbol or more.')

    return pbkdf2_sha256.hash(password, rounds=50000)
