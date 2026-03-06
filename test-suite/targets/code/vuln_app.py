#!/usr/bin/env python3
"""
vuln_app.py - Intentionally vulnerable code for SAST testing.
DO NOT deploy in production.
"""

import os
import sqlite3
import subprocess
import hashlib
import pickle
import yaml

# ── HARDCODED SECRETS ─────────────────────────────────────────────
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD    = "admin123"
JWT_SECRET     = "supersecretkey"
API_KEY        = "sk-proj-abcdef1234567890"

# ── SQL INJECTION ──────────────────────────────────────────────────
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULN: Direct string formatting — SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

# ── COMMAND INJECTION ──────────────────────────────────────────────
def ping_host(host):
    # VULN: shell=True with user input — command injection
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return result

# ── PATH TRAVERSAL ─────────────────────────────────────────────────
def read_file(filename):
    base_dir = "/var/www/uploads/"
    # VULN: No path normalization — path traversal
    with open(base_dir + filename, "r") as f:
        return f.read()

# ── INSECURE DESERIALIZATION ───────────────────────────────────────
def load_session(session_data):
    # VULN: pickle.loads on untrusted data
    return pickle.loads(session_data)

# ── WEAK CRYPTOGRAPHY ──────────────────────────────────────────────
def hash_password(password):
    # VULN: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

# ── YAML UNSAFE LOAD ───────────────────────────────────────────────
def parse_config(config_str):
    # VULN: yaml.load without Loader — arbitrary code execution
    return yaml.load(config_str)

# ── OPEN REDIRECT ──────────────────────────────────────────────────
def redirect_user(request):
    next_url = request.args.get("next")
    # VULN: No whitelist check — open redirect
    return redirect(next_url)

# ── DEBUG MODE / INFO DISCLOSURE ──────────────────────────────────
DEBUG = True
SECRET_FLASK_KEY = "dev-only-key-12345"
