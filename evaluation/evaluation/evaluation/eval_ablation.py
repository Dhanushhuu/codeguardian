#!/usr/bin/env python3
"""
CodeGuardian ablation + Python-transfer evaluation.

Question 1 (ablation): does each detection layer add value on Python code?
    Bandit -> + Semgrep -> + CodeBERT -> (+ your full pipeline, via a hook)
Question 2 (transfer): the CodeBERT model was trained on C functions (Devign / CodeXGLUE).
    Does it carry any signal on Python? Reported as precision / recall / FPR / ROC-AUC.

Unit of evaluation: one snippet = one small Python file. A configuration "flags" a snippet if any
of its layers reports a security finding (at or above the chosen severity) or CodeBERT's
P(vulnerable) >= threshold. Labels: 1 = vulnerable, 0 = safe counterpart.

IMPORTANT LIMITATIONS (state these when you report results):
  * The built-in benchmark is small (24 vulnerable + 24 safe snippets) and was written by hand.
    Its pattern-style cases favour rule-based tools. Treat it as a smoke test, not a benchmark.
    Use --extra-jsonl to add a larger external Python set ({"id","code","label"} per line).
  * With n=24 per class, 95% confidence intervals are wide (printed alongside each rate).
  * Snippet-level detection ignores *which* weakness was found.

Setup (Google Colab, Linux):
    !pip install -q bandit semgrep transformers torch scikit-learn
    # Drive mounted; model folder = output of train_codebert_fixed.py
    !python eval_ablation.py --model-dir "/content/drive/MyDrive/codeguardian/codebert-vulnerability-detector"

Run `python eval_ablation.py --help` for options.
"""
import argparse
import json
import math
import subprocess
import sys
import textwrap
from pathlib import Path

SEV = {"LOW": 0, "INFO": 0, "MEDIUM": 1, "WARNING": 1, "HIGH": 2, "ERROR": 2}

# --------------------------------------------------------------------------------------
# Built-in benchmark: (id, kind, vulnerable_code, safe_code)
# kind = "pattern"  -> a well-known dangerous API/pattern that rule-based tools target
#        "semantic" -> a logic/authorization flaw with no single dangerous call
# --------------------------------------------------------------------------------------
PAIRS = [
    ("sqli_fstring", "pattern", """
        import sqlite3
        def find_user(conn, name):
            cur = conn.cursor()
            cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
            return cur.fetchall()
        """, """
        import sqlite3
        def find_user(conn, name):
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE name = ?", (name,))
            return cur.fetchall()
        """),
    ("sqli_percent", "pattern", """
        def get_orders(db, customer_id):
            query = "SELECT * FROM orders WHERE customer_id = %s" % customer_id
            return db.execute(query).fetchall()
        """, """
        def get_orders(db, customer_id):
            query = "SELECT * FROM orders WHERE customer_id = ?"
            return db.execute(query, (customer_id,)).fetchall()
        """),
    ("cmd_shell_true", "pattern", """
        import subprocess
        def ping(host):
            return subprocess.call("ping -c 1 " + host, shell=True)
        """, """
        import re
        import subprocess
        def ping(host):
            if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
                raise ValueError("invalid host")
            return subprocess.run(["ping", "-c", "1", host], check=False).returncode
        """),
    ("cmd_os_system", "pattern", """
        import os
        def extract(archive_name):
            os.system("tar xzf " + archive_name)
        """, """
        import subprocess
        def extract(archive_name):
            subprocess.run(["tar", "xzf", archive_name], check=True)
        """),
    ("eval_input", "pattern", """
        def calculate(expression):
            return eval(expression)
        """, """
        import ast
        def calculate(expression):
            return ast.literal_eval(expression)
        """),
    ("pickle_loads", "pattern", """
        import pickle
        def load_session(raw_bytes):
            return pickle.loads(raw_bytes)
        """, """
        import json
        def load_session(raw_bytes):
            return json.loads(raw_bytes.decode("utf-8"))
        """),
    ("yaml_load", "pattern", """
        import yaml
        def read_config(text):
            return yaml.load(text)
        """, """
        import yaml
        def read_config(text):
            return yaml.safe_load(text)
        """),
    ("md5_password", "pattern", """
        import hashlib
        def hash_password(password):
            return hashlib.md5(password.encode()).hexdigest()
        """, """
        import hashlib
        import os
        def hash_password(password):
            salt = os.urandom(16)
            return salt + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
        """),
    ("hardcoded_password", "pattern", """
        import psycopg2
        def connect():
            return psycopg2.connect(host="db.internal", user="admin", password="admin123")
        """, """
        import os
        import psycopg2
        def connect():
            return psycopg2.connect(host="db.internal", user=os.environ["DB_USER"],
                                    password=os.environ["DB_PASSWORD"])
        """),
    ("requests_verify_false", "pattern", """
        import requests
        def fetch(url):
            return requests.get(url, verify=False, timeout=10).text
        """, """
        import requests
        def fetch(url):
            return requests.get(url, timeout=10).text
        """),
    ("flask_debug", "pattern", """
        from flask import Flask
        app = Flask(__name__)
        def main():
            app.run(host="0.0.0.0", debug=True)
        """, """
        from flask import Flask
        app = Flask(__name__)
        def main():
            app.run(host="127.0.0.1")
        """),
    ("tempfile_mktemp", "pattern", """
        import tempfile
        def scratch_path():
            return tempfile.mktemp()
        """, """
        import tempfile
        def scratch_file():
            return tempfile.NamedTemporaryFile(delete=False)
        """),
    ("random_token", "pattern", """
        import random
        import string
        def make_token():
            return "".join(random.choice(string.ascii_letters) for _ in range(32))
        """, """
        import secrets
        def make_token():
            return secrets.token_urlsafe(32)
        """),
    ("xml_parse", "pattern", """
        import xml.etree.ElementTree as ET
        def parse_upload(path):
            return ET.parse(path).getroot()
        """, """
        import defusedxml.ElementTree as ET
        def parse_upload(path):
            return ET.parse(path).getroot()
        """),
    ("chmod_777", "pattern", """
        import os
        def publish(path):
            os.chmod(path, 0o777)
        """, """
        import os
        def publish(path):
            os.chmod(path, 0o640)
        """),
    ("jinja_autoescape_off", "pattern", """
        import jinja2
        def render(template_text, **ctx):
            env = jinja2.Environment(autoescape=False)
            return env.from_string(template_text).render(**ctx)
        """, """
        import jinja2
        def render(template_text, **ctx):
            env = jinja2.Environment(autoescape=True)
            return env.from_string(template_text).render(**ctx)
        """),
    ("tar_extractall", "pattern", """
        import tarfile
        def unpack(upload_path, dest):
            with tarfile.open(upload_path) as tar:
                tar.extractall(dest)
        """, """
        import os
        import tarfile
        def unpack(upload_path, dest):
            dest = os.path.realpath(dest)
            with tarfile.open(upload_path) as tar:
                for m in tar.getmembers():
                    target = os.path.realpath(os.path.join(dest, m.name))
                    if not target.startswith(dest + os.sep):
                        raise ValueError("unsafe path in archive")
                tar.extractall(dest)
        """),
    ("missing_authz_delete", "semantic", """
        def delete_invoice(db, current_user, invoice_id):
            invoice = db.get_invoice(invoice_id)
            db.delete(invoice)
            return {"deleted": invoice_id}
        """, """
        def delete_invoice(db, current_user, invoice_id):
            invoice = db.get_invoice(invoice_id)
            if invoice.owner_id != current_user.id:
                raise PermissionError("not your invoice")
            db.delete(invoice)
            return {"deleted": invoice_id}
        """),
    ("idor_read_order", "semantic", """
        def get_order(db, current_user, order_id):
            return db.query("orders").filter(id=order_id).first()
        """, """
        def get_order(db, current_user, order_id):
            return db.query("orders").filter(id=order_id, user_id=current_user.id).first()
        """),
    ("timing_token_compare", "semantic", """
        def verify_token(supplied, stored):
            return supplied == stored
        """, """
        import hmac
        def verify_token(supplied, stored):
            return hmac.compare_digest(supplied, stored)
        """),
    ("path_traversal_open", "semantic", """
        import os
        BASE_DIR = "/srv/uploads"
        def read_upload(filename):
            with open(os.path.join(BASE_DIR, filename), "rb") as f:
                return f.read()
        """, """
        import os
        BASE_DIR = os.path.realpath("/srv/uploads")
        def read_upload(filename):
            path = os.path.realpath(os.path.join(BASE_DIR, filename))
            if not path.startswith(BASE_DIR + os.sep):
                raise ValueError("invalid path")
            with open(path, "rb") as f:
                return f.read()
        """),
    ("open_redirect", "semantic", """
        from flask import redirect, request
        def after_login():
            return redirect(request.args.get("next", "/"))
        """, """
        from flask import redirect, request
        ALLOWED = {"/", "/dashboard", "/profile"}
        def after_login():
            target = request.args.get("next", "/")
            return redirect(target if target in ALLOWED else "/")
        """),
    ("ssrf_fetch", "semantic", """
        import requests
        def preview(url):
            return requests.get(url, timeout=5).text[:500]
        """, """
        import requests
        from urllib.parse import urlparse
        ALLOWED_HOSTS = {"example.com", "cdn.example.com"}
        def preview(url):
            if urlparse(url).hostname not in ALLOWED_HOSTS:
                raise ValueError("host not allowed")
            return requests.get(url, timeout=5).text[:500]
        """),
    ("jwt_no_verify", "semantic", """
        import jwt
        def current_user_id(token):
            claims = jwt.decode(token, options={"verify_signature": False})
            return claims["sub"]
        """, """
        import jwt
        def current_user_id(token, key):
            claims = jwt.decode(token, key, algorithms=["HS256"])
            return claims["sub"]
        """),
]


def build_benchmark():
    items = []
    for pid, kind, vuln, safe in PAIRS:
        items.append({"id": f"{pid}__vuln", "kind": kind, "label": 1,
                      "code": textwrap.dedent(vuln).strip() + "\n"})
        items.append({"id": f"{pid}__safe", "kind": kind, "label": 0,
                      "code": textwrap.dedent(safe).strip() + "\n"})
    return items


# --------------------------------------------------------------------------------------
# Tool runners
# --------------------------------------------------------------------------------------
def run_bandit(folder):
    """Return {filename: [{'sev': int, 'id': str}]}."""
    p = subprocess.run(["bandit", "-r", str(folder), "-f", "json", "-q"],
                       capture_output=True, text=True)
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"bandit produced no JSON. stderr: {p.stderr[:500]}")
    out = {}
    for r in data.get("results", []):
        out.setdefault(Path(r["filename"]).name, []).append(
            {"sev": SEV[r["issue_severity"].upper()], "id": r["test_id"]})
    return out


def run_semgrep(folder, config):
    p = subprocess.run(["semgrep", "--config", config, "--json", "--quiet",
                        "--metrics=off", str(folder)], capture_output=True, text=True)
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"semgrep produced no JSON. stderr: {p.stderr[:500]}")
    out = {}
    for r in data.get("results", []):
        sev = r.get("extra", {}).get("severity", "INFO").upper()
        out.setdefault(Path(r["path"]).name, []).append(
            {"sev": SEV.get(sev, 0), "id": r["check_id"].split(".")[-1]})
    return out


def run_codebert(model_dir, codes):
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    tok = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir).to(dev).eval()
    probs = []
    for i in range(0, len(codes), 8):
        enc = tok(codes[i:i + 8], truncation=True, max_length=512, padding=True,
                  return_tensors="pt").to(dev)
        with torch.no_grad():
            logits = model(**enc).logits
        probs += torch.softmax(logits, dim=-1)[:, 1].tolist()
    return probs


def pipeline_flag(code, name):
    """HOOK: return True/False if your FULL CodeGuardian pipeline reports a security finding for
    this snippet, or None to skip that row. Implement by calling your FastAPI endpoint or graph,
    e.g. requests.post(<your /review endpoint>, json={...}) and checking the returned findings.
    Run it with --use-pipeline once implemented."""
    return None


# --------------------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------------------
def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    a = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - a) / d, (c + a) / d)


def rate(k, n):
    if n == 0:
        return {"value": None, "ci": None, "k": k, "n": n}
    return {"value": k / n, "ci": wilson(k, n), "k": k, "n": n}


def metrics(labels, flags):
    tp = sum(1 for y, f in zip(labels, flags) if y == 1 and f)
    fn = sum(1 for y, f in zip(labels, flags) if y == 1 and not f)
    fp = sum(1 for y, f in zip(labels, flags) if y == 0 and f)
    tn = sum(1 for y, f in zip(labels, flags) if y == 0 and not f)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": rate(tp, tp + fp), "recall": rate(tp, tp + fn), "fpr": rate(fp, fp + tn)}


def fmt(r):
    if r["value"] is None:
        return "n/a"
    lo, hi = r["ci"]
    return f"{r['value']*100:.0f}% ({r['k']}/{r['n']}; CI {lo*100:.0f}-{hi*100:.0f}%)"


# --------------------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------------------
def evaluate(name, items, args, workdir):
    folder = workdir / name
    folder.mkdir(parents=True, exist_ok=True)
    for it in items:
        (folder / f"{it['id']}.py").write_text(it["code"])
    fname = {it["id"]: f"{it['id']}.py" for it in items}
    labels = [it["label"] for it in items]

    print(f"[{name}] {len(items)} snippets ({sum(labels)} vulnerable, {len(labels)-sum(labels)} safe)")
    bandit = run_bandit(folder)
    semgrep = None
    if not args.skip_semgrep:
        try:
            semgrep = run_semgrep(folder, args.semgrep_config)
        except (RuntimeError, FileNotFoundError) as e:
            print(f"  semgrep skipped: {e}")
    probs = None
    if args.model_dir:
        probs = run_codebert(args.model_dir, [it["code"] for it in items])
    pipeline = None
    if args.use_pipeline:
        pipeline = [pipeline_flag(it["code"], it["id"]) for it in items]
        if all(p is None for p in pipeline):
            pipeline = None

    result = {"n": len(items), "n_vulnerable": sum(labels), "settings": {}}
    for tag, thr in (("all severities", 0), ("MEDIUM and above", 1)):
        b = [any(f["sev"] >= thr for f in bandit.get(fname[it["id"]], [])) for it in items]
        s = ([any(f["sev"] >= thr for f in semgrep.get(fname[it["id"]], [])) for it in items]
             if semgrep is not None else None)
        c = [p >= args.cb_threshold for p in probs] if probs is not None else None
        configs = {"Bandit only": b}
        if s is not None:
            configs["Bandit + Semgrep"] = [x or y for x, y in zip(b, s)]
            if c is not None:
                configs["Bandit + Semgrep + CodeBERT"] = [x or y or z for x, y, z in zip(b, s, c)]
        if c is not None:
            configs["CodeBERT alone (C -> Python transfer)"] = c
        if pipeline is not None:
            configs["Full pipeline (+ LLM triage)"] = [bool(p) for p in pipeline]

        rows = {}
        for cname, flags in configs.items():
            m = metrics(labels, flags)
            by_kind = {}
            for kind in ("pattern", "semantic"):
                idx = [i for i, it in enumerate(items) if it["label"] == 1 and it.get("kind") == kind]
                if idx:
                    by_kind[kind] = rate(sum(1 for i in idx if flags[i]), len(idx))
            m["recall_by_kind"] = by_kind
            rows[cname] = m
        result["settings"][tag] = rows

    if probs is not None:
        v = [p for p, y in zip(probs, labels) if y == 1]
        sf = [p for p, y in zip(probs, labels) if y == 0]
        cb = {"mean_prob_vulnerable": sum(v) / len(v), "mean_prob_safe": sum(sf) / len(sf),
              "threshold": args.cb_threshold}
        try:
            from sklearn.metrics import roc_auc_score
            cb["roc_auc"] = float(roc_auc_score(labels, probs))
        except Exception:
            cb["roc_auc"] = None
        result["codebert_scores"] = cb

    result["per_snippet"] = [
        {"id": it["id"], "label": it["label"], "kind": it.get("kind"),
         "bandit": [f["id"] for f in bandit.get(fname[it["id"]], [])],
         "semgrep": [f["id"] for f in (semgrep or {}).get(fname[it["id"]], [])],
         "codebert_prob": (round(probs[i], 3) if probs is not None else None)}
        for i, it in enumerate(items)]
    return result


def to_markdown(all_results, primary):
    lines = ["# Ablation and Python-transfer results (auto-generated)", ""]
    for bname, res in all_results.items():
        lines += [f"## Benchmark: {bname} ({res['n']} snippets, {res['n_vulnerable']} vulnerable)", ""]
        for tag, rows in res["settings"].items():
            star = " (primary)" if tag == primary else ""
            lines += [f"### Severity filter: {tag}{star}", "",
                      "| Configuration | Precision | Recall | False-positive rate | TP/FP/FN/TN |",
                      "|---|---|---|---|---|"]
            for cname, m in rows.items():
                lines.append(f"| {cname} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['fpr'])} | "
                             f"{m['tp']}/{m['fp']}/{m['fn']}/{m['tn']} |")
            lines += ["", "Recall by weakness type:", "",
                      "| Configuration | Pattern-style | Semantic (logic/authz) |", "|---|---|---|"]
            for cname, m in rows.items():
                k = m["recall_by_kind"]
                lines.append(f"| {cname} | {fmt(k['pattern']) if 'pattern' in k else 'n/a'} | "
                             f"{fmt(k['semantic']) if 'semantic' in k else 'n/a'} |")
            lines.append("")
        if "codebert_scores" in res:
            cb = res["codebert_scores"]
            auc = f"{cb['roc_auc']:.3f}" if cb.get("roc_auc") is not None else "n/a"
            lines += ["CodeBERT score distribution (transfer check):", "",
                      f"- ROC-AUC on this benchmark: **{auc}** (0.5 = chance)",
                      f"- Mean P(vulnerable): vulnerable snippets {cb['mean_prob_vulnerable']:.3f}, "
                      f"safe snippets {cb['mean_prob_safe']:.3f}", ""]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model-dir", help="Fine-tuned CodeBERT folder (omit to skip CodeBERT rows)")
    ap.add_argument("--semgrep-config", default="p/python", help="Semgrep ruleset (default p/python)")
    ap.add_argument("--skip-semgrep", action="store_true")
    ap.add_argument("--cb-threshold", type=float, default=0.5)
    ap.add_argument("--extra-jsonl", help='Extra Python set, one {"id","code","label"} per line')
    ap.add_argument("--use-pipeline", action="store_true", help="Call pipeline_flag() hook")
    ap.add_argument("--primary", default="all severities",
                    choices=["all severities", "MEDIUM and above"],
                    help="Which severity filter to mark primary (match what your pipeline reports)")
    ap.add_argument("--workdir", default="eval_work")
    ap.add_argument("--out", default="eval_out")
    args = ap.parse_args()

    workdir, out = Path(args.workdir), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    benchmarks = {"builtin": build_benchmark()}
    if args.extra_jsonl:
        extra = []
        for line in Path(args.extra_jsonl).read_text().splitlines():
            if line.strip():
                d = json.loads(line)
                extra.append({"id": str(d["id"]), "kind": d.get("kind"), "label": int(d["label"]),
                              "code": d["code"]})
        benchmarks["extra"] = extra

    results = {name: evaluate(name, items, args, workdir) for name, items in benchmarks.items()}
    (out / "results.json").write_text(json.dumps(results, indent=2))
    md = to_markdown(results, args.primary)
    (out / "results.md").write_text(md)
    print(md)
    print(f"\nSaved {out/'results.json'} and {out/'results.md'}")


if __name__ == "__main__":
    sys.exit(main())
