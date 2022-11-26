import os
import random
import string
import re
import json

from flask import (
    request,
    session,
    redirect,
)
from functools import wraps
from datetime import datetime
from base64 import b64decode


def get_csrf_session(override_endpoint: str = None):
    csrf_value = random_string()

    d = {}
    if "csrf_values" in session:
        d = session["csrf_values"]

    d.update({override_endpoint if override_endpoint else request.endpoint: csrf_value})
    session["csrf_values"] = d

    return csrf_value


def CheckCSRFSession(f):
    @wraps(f)
    def wrap(*args, **kwds):
        valid = True

        if "csrf_values" in session and type(session["csrf_values"]) == dict:
            ep = request.endpoint

            if request.method == "POST" and ep in session["csrf_values"]:
                valid = False
                try:
                    from_request = request.form["csrf_form"].strip()
                    session_value = session["csrf_values"][ep]
                    if session_value == from_request:
                        valid = True
                    session["csrf_values"].pop(ep)
                except Exception as e:
                    print("check_csrf_session:e:", e)

        if valid:
            return f(*args, **kwds)
        else:
            return "Forbidden", 403

    return wrap


def sanitise_string(
    s: str,
    allow_numbers: bool = True,
    allow_letters: bool = True,
    allow_lower: bool = True,
    allow_upper: bool = True,
    allow_space: bool = True,
    allow_accented_chars: bool = True,
    allow_single_quotes: bool = True,
    allow_hyphen: bool = True,
    allow_underscore: bool = False,
    allow_at_symbol: bool = False,
    additional_allowed_chars: list = [],
    normalise_single_quotes: bool = True,
    perform_lower: bool = False,
    perform_upper: bool = False,
    perform_title: bool = False,
    reverse: bool = False,
    max_length: int = 200,
) -> str:
    regex_string = "[^"
    regex_string += "a-z" if allow_letters and allow_lower else ""
    regex_string += "A-Z" if allow_letters and allow_upper else ""
    regex_string += "0-9" if allow_numbers else ""
    regex_string += "A-ZÀ-ÖØ-öø-ÿ" if allow_letters and allow_accented_chars else ""
    regex_string += "'’′`" if allow_single_quotes else ""
    regex_string += " " if allow_space else ""
    regex_string += "\\-" if allow_hyphen else ""
    regex_string += "_" if allow_underscore else ""
    regex_string += "@" if allow_at_symbol else ""
    regex_string += "".join(additional_allowed_chars)
    regex_string += "]"

    full_pattern = re.compile(regex_string)
    s = re.sub(full_pattern, "", s)

    if normalise_single_quotes:
        s = re.sub(r"[’′`]", "'", s)

    if perform_lower:
        s = s.lower()

    if perform_upper:
        s = s.upper()

    if perform_title:
        s = s.title()

    if reverse:
        s = s[::-1]

    return s[:max_length]


def random_string(
    length: int = 32, lower: bool = False, only_numbers: bool = False
) -> str:
    if only_numbers:
        chars = string.digits
    else:
        chars = string.digits + string.ascii_letters
    res = "".join(random.choice(chars) for i in range(length))
    if lower:
        res = res.lower()
    return res