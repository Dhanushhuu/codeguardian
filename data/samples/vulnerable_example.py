import os
import pickle
import hashlib
import subprocess
import random
import sqlite3
import requests


# --- [1] SQL Injection -------------------------------------------------------
def get_user_by_id(user_id, conn):
    cursor = conn.cursor()
    # VULN: direct string concatenation in SQL
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()


# --- [2] OS Command Injection ------------------------------------------------
def ping_host(hostname):
    # VULN: shell=True with user-controlled input
    result = subprocess.run(
        "ping -c 1 " + hostname,
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


# --- [3] Hardcoded Credentials -----------------------------------------------
def connect_to_db():
    # VULN: hardcoded password committed to source control
    password = "super_secret_db_pass_123"
    api_key  = "sk-prod-abc123def456ghi789"
    return {"host": "db.internal", "password": password, "api_key": api_key}


# --- [4] Insecure Deserialization --------------------------------------------
def load_user_session(session_data):
    # VULN: unpickling untrusted user-supplied data
    return pickle.loads(session_data)


# --- [5] Weak Cryptography ---------------------------------------------------
def hash_user_password(password):
    # VULN: MD5 is cryptographically broken for password hashing
    return hashlib.md5(password.encode()).hexdigest()


# --- [6] Arbitrary Code Execution --------------------------------------------
def calculate(expression):
    # VULN: eval() on user input allows arbitrary code execution
    return eval(expression)


# --- [7] Insecure Randomness -------------------------------------------------
def generate_token(length=32):
    # VULN: random.choice is not cryptographically secure
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.choice(chars) for _ in range(length))


# --- [8] TLS Verification Disabled -------------------------------------------
def fetch_user_data(user_id):
    # VULN: verify=False disables TLS certificate validation
    url = "https://api.internal.corp/users/" + user_id
    resp = requests.get(url, verify=False, timeout=10)
    return resp.json()


# --- [9] OS System Command ---------------------------------------------------
def run_report(report_name):
    # VULN: os.system with user input
    os.system("generate_report " + report_name)