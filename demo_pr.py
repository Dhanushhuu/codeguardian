from __future__ import annotations
 
import argparse
import os
import time
from dotenv import load_dotenv
 
load_dotenv()
 
VULNERABLE_CODE = '''"""
demo_vulnerable.py - CodeGuardian Demo File
This file contains deliberate security vulnerabilities for demonstration.
DO NOT use in production.
"""
import pickle
import subprocess
import hashlib
import os
import sqlite3
 
 
def get_user(user_id, conn):
    cursor = conn.cursor()
    # VULN 1: SQL Injection - string concatenation in SQL query
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
 
 
def run_command(user_input):
    # VULN 2: Command Injection - shell=True with user input
    result = subprocess.run(user_input, shell=True, capture_output=True, text=True)
    return result.stdout
 
 
def load_session(session_bytes):
    # VULN 3: Insecure Deserialization - pickle on untrusted data
    return pickle.loads(session_bytes)
 
 
def hash_password(password):
    # VULN 4: Weak Cryptography - MD5 is broken for passwords
    return hashlib.md5(password.encode()).hexdigest()
 
 
def authenticate(username, password):
    # VULN 5: Hardcoded Credentials
    admin_password = "admin123secret"
    api_key = "sk-live-abc123xyz789"
    if password == admin_password:
        return True
    return False
 
 
def evaluate_expression(expr):
    # VULN 6: Arbitrary Code Execution - eval on user input
    return eval(expr)
'''
 
 
def create_demo_pr(repo_name: str) -> None:
    try:
        from github import Github, GithubException
    except ImportError:
        print("ERROR: PyGithub not installed. Run: pip install PyGithub")
        return
 
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("ERROR: GITHUB_TOKEN not set in .env")
        return
 
    gh   = Github(token)
    repo = gh.get_repo(repo_name)
 
    # Get default branch
    default_branch = repo.default_branch
    base_sha       = repo.get_branch(default_branch).commit.sha
    print(f"Repo      : {repo_name}")
    print(f"Base      : {default_branch} ({base_sha[:8]})")
 
    # Create a new branch
    branch_name = f"demo/codeguardian-test-{int(time.time())}"
    repo.create_git_ref(
        ref = f"refs/heads/{branch_name}",
        sha = base_sha,
    )
    print(f"Branch    : {branch_name} created")
 
    # Create the vulnerable file on that branch
    repo.create_file(
        path    = "demo_vulnerable.py",
        message = "Add demo vulnerable file for CodeGuardian review",
        content = VULNERABLE_CODE,
        branch  = branch_name,
    )
    print(f"File      : demo_vulnerable.py pushed")
 
    # Open a PR
    pr = repo.create_pull(
        title = "Demo: CodeGuardian Security Review",
        body  = (
            "This PR contains deliberately vulnerable code to demonstrate "
            "CodeGuardian's autonomous security review capabilities.\n\n"
            "**CodeGuardian will automatically:**\n"
            "- Detect SQL injection, command injection, insecure deserialization\n"
            "- Generate code fixes with syntax validation\n"
            "- Post a structured security report as a comment\n"
            "- Generate a PDF audit report\n\n"
            "_DO NOT merge — for demo purposes only._"
        ),
        head  = branch_name,
        base  = default_branch,
    )
    print(f"\nPR created: {pr.html_url}")
    print(f"\nCodeGuardian will now:")
    print(f"  1. Receive the webhook")
    print(f"  2. Run the full pipeline (~40 seconds)")
    print(f"  3. Post a security report comment on the PR")
    print(f"\nWatch your uvicorn terminal for pipeline logs.")
    print(f"Then check the PR page for the CodeGuardian comment!")
 
 
def main():
    parser = argparse.ArgumentParser(description="Create demo PR for CodeGuardian")
    parser.add_argument(
        "--repo",
        required=True,
        help="GitHub repo in format: username/reponame",
    )
    args = parser.parse_args()
    create_demo_pr(args.repo)
 
 
if __name__ == "__main__":
    main()