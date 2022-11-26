import json
import base64
import time
import traceback
import re
import os
import html
import werkzeug

from datetime import timedelta
from flask import (
    Flask,
    jsonify,
    send_from_directory,
    render_template,
    request,
    session,
    redirect,
    make_response,
    url_for
)
from apig_wsgi import make_lambda_handler
from urllib.parse import parse_qs, unquote
from generate_utils import get_csrf_session, CheckCSRFSession

ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

IS_PROD = "production" == ENVIRONMENT.lower()
RAW_IS_HTTPS = os.getenv("IS_HTTPS", "f").lower()
IS_HTTPS = RAW_IS_HTTPS.startswith("t") or RAW_IS_HTTPS == "1"

COOKIE_PREFIX = "__Host-" if IS_HTTPS else ""
COOKIE_NAME_SESSION = f"{COOKIE_PREFIX}Session"

PORT = int(os.getenv("PORT", "5001"))
DOMAIN = os.getenv("DOMAIN", f"localhost:{PORT}")
URL_PREFIX = os.getenv("URL_PREFIX", f"http{'s' if IS_HTTPS else ''}://{DOMAIN}")

app = Flask(__name__)

if ENVIRONMENT != "production":
    app.config["TESTING"] = True
    app.config["DEBUG"] = True
    app.testing = True

app.config.update(
    ENV=ENVIRONMENT,
    SESSION_COOKIE_NAME=COOKIE_NAME_SESSION,
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_PATH="/",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=IS_HTTPS,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY", "123"),
    MAX_CONTENT_LENGTH=120 * 1024 * 1024,
)

assets = werkzeug.utils.safe_join(os.path.dirname(__file__), "assets")
alb_lambda_handler = make_lambda_handler(app)



def client_ip():
    if request.environ.get("HTTP_X_FORWARDED_FOR") is None:
        return request.environ["REMOTE_ADDR"]
    else:
        return request.environ["HTTP_X_FORWARDED_FOR"]


def lambda_handler(event, context):
    try:
        response = alb_lambda_handler(event, context)
        print(json.dumps(
            {
                "Request": event,
                "Response": {
                    "statusCode": response["statusCode"],
                    "headers": response["headers"],
                    "body_length": len(response["body"]),
                },
            }
        ), default=str)
        return response
    except Exception as e:
        print(json.dumps({"Request": event, "Response": None, "Error": traceback.format_exc()}), default=str)
        return {"statusCode": 500}


@app.route("/internal/<check>")
def health_check(check="health"):
    if check == "health":
        return "IMOK {}".format(check)
    else:
        return "FAIL dependencies"

@app.route("/", methods=["GET"])
def root():
    return render_template(
        "index.html",
        **{
            "title": "Home",
            "url_prefix": URL_PREFIX,
            "domain": DOMAIN,
        }
    )

scan_defaults = {
    "p": "none",
    "sp": "none",
    "po": "*",
    "src": "*",
    "sbd": ".",
    "ruh": None,
    "rua": None,
    "ruf": None,
    "ri": 86400,
    "rf": "json",
    "so": "passive",
    "pr": 0,
    "vf": None,
    "alt": None,
    "nbf": None,
    "exp": None,
    "inc": None,
    "rqs": "no",
    "esa": None,
}

@app.route("/scan", methods=["GET", "POST"])
@CheckCSRFSession
def scan():
    if "records" not in session:
        session["records"] = []

    if request.method == "POST":
        record = {}

        for k in [
            "p",
            "sp",
            "po",
            "src",
            "sbd",
            "ruh",
            "rua",
            "ruf",
            "ri",
            "rf",
            "so",
            "pr",
            "vf",
            "alt",
            "nbf",
            "exp",
            "inc",
            "rqs",
            "esa",
        ]:
            record[k] = request.form.get(k, scan_defaults[k])
        
        if record["inc"]:
            record = {"inc": record["inc"]}

        session["records"].append(record)

    return render_template(
        "scan.html",
        **{
            "csrf_form": get_csrf_session(),
            "records": session["records"],
            "title": "Scan",
            "url_prefix": URL_PREFIX,
            "domain": DOMAIN,
        }
    )
