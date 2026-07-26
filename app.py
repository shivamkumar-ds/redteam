from flask import Flask, request, jsonify
from pathlib import Path
from urllib.parse import urlparse, urljoin
import requests
import socket
import ipaddress

app = Flask(__name__)

ROOT = Path("/srv/agent-redteam/sandbox-f620c09828").resolve()

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org"
}

#######################################################
# FILE GUARDRAIL
#######################################################

def read_file_secure(user_path: str):

    candidate = (ROOT / user_path).resolve(strict=False)

    try:
        candidate.relative_to(ROOT)
    except ValueError:
        return {
            "action": "block",
            "reason": "path traversal detected",
            "result": None
        }

    if not candidate.exists():
        return {
            "action": "block",
            "reason": "file not found",
            "result": None
        }

    if not candidate.is_file():
        return {
            "action": "block",
            "reason": "not a file",
            "result": None
        }

    with open(candidate, "r", encoding="utf-8") as f:
        content = f.read()

    return {
        "action": "allow",
        "reason": "inside sandbox",
        "result": content
    }


#######################################################
# SSRF GUARDRAIL
#######################################################

def ip_safe(ip):

    ip = ipaddress.ip_address(ip)

    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_host(host):

    if host.lower() not in ALLOWED_HOSTS:
        return False

    try:
        infos = socket.getaddrinfo(host, None)

        for info in infos:
            ip = info[4][0]

            if not ip_safe(ip):
                return False

    except Exception:
        return False

    return True


def fetch_secure(url):

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return {
            "action": "block",
            "reason": "invalid scheme",
            "result": None
        }

    if parsed.username or parsed.password:
        return {
            "action": "block",
            "reason": "userinfo not allowed",
            "result": None
        }

    if not parsed.hostname:
        return {
            "action": "block",
            "reason": "missing hostname",
            "result": None
        }

    current = url

    for _ in range(5):

        parsed = urlparse(current)

        host = parsed.hostname

        if not validate_host(host):
            return {
                "action": "block",
                "reason": "host not allowed",
                "result": None
            }

        response = requests.get(
            current,
            timeout=5,
            allow_redirects=False
        )

        if response.is_redirect:

            location = response.headers.get("Location")

            if not location:
                break

            current = urljoin(current, location)
            continue

        return {
            "action": "allow",
            "reason": "host allowed",
            "result": response.text
        }

    return {
        "action": "block",
        "reason": "too many redirects",
        "result": None
    }


#######################################################
# API
#######################################################

@app.route("/", methods=["GET"])
def health():
    return "Guardrail Running"


@app.route("/", methods=["POST"])
def guardrail():

    data = request.get_json(force=True)

    tool = data.get("tool")
    args = data.get("arguments", {})

    if tool == "read_file":
        return jsonify(read_file_secure(args.get("path", "")))

    elif tool == "fetch_url":
        return jsonify(fetch_secure(args.get("url", "")))

    return jsonify({
        "action": "block",
        "reason": "unknown tool",
        "result": None
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
