<div align="center">

# 🛡️ CodeGuardian

### Autonomous Code Security & Quality Review Agent

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2-FF6B35?style=for-the-badge&logo=langchain&logoColor=white)](https://langchain.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Cost](https://img.shields.io/badge/Total%20Cost-$0-brightgreen?style=for-the-badge)](.)

<br/>

> **Submit a Pull Request — CodeGuardian scans it with 3 detection layers running in parallel,
> generates validated code fixes, writes missing tests, and posts a structured security report
> directly on your PR. Automatically. In ~40 seconds.**

<br/>

Built by **Dhanush Kumar** · Final Year B.E. (AIML) · 2026

</div>

---

## 📋 Table of Contents

- [What It Does](#-what-it-does)
- [How It Works](#-how-it-works)
- [Detection Layers](#-detection-layers)
- [Why CodeGuardian](#-why-codeguardian)
- [Real Results](#-real-results)
- [Quick Start](#-quick-start)
- [API Reference](#-api-reference)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)

---

## 🎯 What It Does

CodeGuardian is a **production-grade multi-agent AI system** that automates the entire code security review process. When a developer opens a Pull Request, CodeGuardian:

1. **Detects vulnerabilities** using 3 parallel scanning layers (static analysis + ML + LLM)
2. **Filters false positives** using an LLM that explains why each finding is real or noise
3. **Generates code fixes** with category-specific templates, validated with `ast.parse()`
4. **Writes unit tests** covering the fixed functions, targeting the exact vulnerabilities found
5. **Posts a structured report** directly as a GitHub PR comment with verdict, severity breakdown, and collapsible issue details
6. **Generates a PDF report** for documentation and audit trails

---

## ⚙️ How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    GitHub Pull Request                       │
└─────────────────────────┬───────────────────────────────────┘
                          │ webhook
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                     PARSER AGENT                            │
│         Language detection · AST extraction                  │
│         Function-level code unit isolation                   │
└──────────────────┬──────────────────────────────────────────┘
                   │
        ┌──────────┴──────────┐
        │   LangGraph fan-out  │  ← runs in parallel
        ▼                     ▼
┌───────────────┐    ┌─────────────────┐
│ SECURITY      │    │ QUALITY AGENT   │
│ AGENT         │    │                 │
│               │    │ · Radon CC/MI   │
│ · Bandit      │    │ · AST checks    │
│   68 checks   │    │   - Long funcs  │
│ · Semgrep     │    │   - Deep nesting│
│   1000+ rules │    │   - Missing docs│
│ · CodeBERT    │    │ · LLM review    │
│   ML model    │    │   - Naming      │
│ · LLM enrich  │    │   - SRP         │
│   FP filter   │    │   - Duplication │
└───────┬───────┘    └────────┬────────┘
        └──────────┬──────────┘
                   │ merged results
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                      FIX AGENT                              │
│   Category-specific fix templates · ast.parse() validation  │
│   SQL injection → parameterized queries                      │
│   Shell injection → list args, no shell=True                 │
│   Hardcoded secrets → os.getenv()                            │
│   Weak crypto → SHA-256 / bcrypt                             │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   TEST WRITER AGENT                         │
│   pytest (Python) · jest (JS/TS)                            │
│   Happy path + edge cases + security regression tests        │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    REVIEWER AGENT                           │
│   Verdict · GitHub PR comment · PDF report                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔍 Detection Layers

| # | Layer | Tool | What It Catches |
|---|---|---|---|
| 1 | **Static Analysis** | Bandit | 68 Python checks — SQL injection (CWE-89), shell injection (CWE-78), hardcoded passwords (CWE-259), weak crypto (CWE-327), insecure deserialization (CWE-502) |
| 2 | **Pattern Matching** | Semgrep | 1000+ community rules — Python, JavaScript, TypeScript, JSX, TSX. Custom YAML rules supported. |
| 3 | **ML Classification** | CodeBERT | Function-level binary classifier fine-tuned on CodeXGLUE Defect Detection (Devign dataset). Catches contextual/logic-level vulnerabilities static tools miss. |
| 4 | **LLM Enrichment** | LLaMA 3.3 70B | Reviews all scanner findings, dismisses false positives with explanation, adds exploitation context, surfaces issues scanners missed. |

---

## 🏆 Why CodeGuardian

| Feature | GitHub Copilot | SonarQube | **CodeGuardian** |
|---|---|---|---|
| Multi-layer detection | ❌ | Partial | ✅ Bandit + Semgrep + CodeBERT |
| Fine-tuned ML classifier | ❌ | ❌ | ✅ CodeBERT on CodeXGLUE |
| Auto-generated fixes | ❌ | ❌ | ✅ Syntax validated |
| Auto-generated tests | ❌ | ❌ | ✅ pytest + jest |
| LLM false positive filtering | ❌ | ❌ | ✅ Explains every dismissal |
| Parallel agent execution | ❌ | ❌ | ✅ LangGraph fan-out |
| Posts PR comment | ✅ | ❌ | ✅ Structured markdown |
| PDF audit report | ❌ | Paid | ✅ Free |
| **Total cost** | **Paid** | **Paid** | **$0** |

---

## 📊 Real Results

Tested on `data/samples/vulnerable_example.py` — 9 deliberate vulnerabilities:

```
CODEGUARDIAN REPORT
════════════════════════════════════════════════════
Verdict  : REQUEST_CHANGES
Summary  : Found 24 security issue(s) and 18 quality issue(s)
           across 1 file(s). 0 false positive(s) dismissed.
           10 fix(es) and 0 test file(s) generated.

Severity Breakdown:
  🔴 Critical : 0
  🟠 High     : 13
  🟡 Medium   : 7
  🔵 Low      : 4

Issues Detected:
  [HIGH  ] Subprocess Popen With Shell Equals True (line 24) [bandit]
  [HIGH  ] Request With No Cert Validation        (line 68) [bandit]
  [HIGH  ] Start Process With A Shell             (line 75) [bandit]
  [HIGH  ] Subprocess Shell True                  (line 24) [semgrep]
  [HIGH  ] Shell Injection                        (line 24) [codebert]
  [HIGH  ] Insecure Deserialization               (line 40) [codebert]
  [HIGH  ] Arbitrary Code Execution               (line 52) [codebert]
  [HIGH  ] TLS Verification Disabled              (line 65) [codebert]
  [HIGH  ] Insecure API Key Storage               (line 20) [llm]

Detection Rate : 9/9 vulnerabilities found = 100%
Pipeline Time  : ~40 seconds end-to-end
Fix Validation : 9/10 fixes passed ast.parse()
════════════════════════════════════════════════════
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+ (frontend only)
- [Groq API key](https://console.groq.com) (free)
- [GitHub Token](https://github.com/settings/tokens) (free)

### Setup

```bash
git clone https://github.com/Dhanushhuu/codeguardian
cd codeguardian

# Create virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Mac/Linux

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env — add GROQ_API_KEY and GITHUB_TOKEN
```

### Run

```bash
# Start the API server
uvicorn api.main:app --reload --port 8000

# In a new terminal — run a review
python run_review.py

# Open Swagger UI
# http://localhost:8000/docs
```

### Frontend

```bash
cd frontend
npm install
npm run dev
# Open http://localhost:5173
```

### Test

```bash
# Tool-level tests (no API key needed)
python tests/test_pipeline.py --tools-only

# Full pipeline test (needs GROQ_API_KEY)
python tests/test_pipeline.py
```

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Health check |
| `POST` | `/review` | Submit code for manual review |
| `GET` | `/status/{id}` | Job status + live event log |
| `GET` | `/stream/{id}` | SSE stream of agent activity |
| `GET` | `/results/{id}` | Full JSON report |
| `GET` | `/results/{id}/pdf` | Download PDF report |
| `POST` | `/webhook/github` | GitHub PR webhook receiver |

**Example:**

```bash
python run_review.py
# Submits vulnerable_example.py and polls for results
# Saves full report to review_result.json
```

---

## 🛠 Tech Stack — Total Cost: $0

| Component | Technology | Why |
|---|---|---|
| **Agent Framework** | LangGraph | Parallel fan-out, state management |
| **LLM** | Groq — LLaMA 3.3 70B | Free tier, fastest inference (~200 tok/s) |
| **Python Security** | Bandit | 68 checks, CWE + OWASP mapping |
| **Multi-lang Security** | Semgrep | 1000+ maintained community rules |
| **ML Classifier** | CodeBERT (microsoft) | Function-level vulnerability detection |
| **ML Dataset** | CodeXGLUE Defect Detection | 21,854 labeled C functions |
| **Code Quality** | Radon | Cyclomatic complexity + maintainability index |
| **GitHub Integration** | PyGithub + Webhooks | PR comment posting |
| **PDF Reports** | ReportLab | Audit-ready PDF generation |
| **Backend** | FastAPI + SSE | Async, streaming, auto-docs |
| **Frontend** | React + Vite | Dark dashboard, live event log |

---

## 📁 Project Structure

```
codeguardian/
├── agents/
│   ├── parser_agent.py        # File parsing + AST function extraction
│   ├── security_agent.py      # 3-layer parallel scan + LLM enrichment
│   ├── quality_agent.py       # Radon + AST + LLM quality review
│   ├── fix_agent.py           # Template-guided fixes + ast.parse() validation
│   ├── test_writer_agent.py   # pytest/jest test generation
│   └── reviewer_agent.py      # Verdict + GitHub PR comment + PDF report
│
├── tools/
│   ├── pr_parser.py           # Language detection + AST function extraction
│   ├── bandit_scanner.py      # Bandit with CWE + OWASP mapping
│   ├── semgrep_scanner.py     # Multi-language Semgrep integration
│   ├── codebert_classifier.py # CodeBERT base + fine-tuned inference
│   └── quality_analyzer.py   # Radon CC/MI + AST quality checks
│
├── graph/
│   ├── state.py               # ReviewState TypedDict (Annotated for parallel nodes)
│   └── pipeline.py            # LangGraph graph — fan-out + fan-in
│
├── api/
│   └── main.py                # FastAPI + webhook + SSE streaming + PDF download
│
├── frontend/
│   └── src/App.jsx            # React dark dashboard with live agent log
│
├── finetuning/
│   └── train.py               # CodeBERT LoRA fine-tuning on CodeXGLUE
│
├── data/
│   └── samples/
│       └── vulnerable_example.py  # 9 deliberate vulnerabilities for testing
│
├── tests/
│   └── test_pipeline.py       # Integration + tool-level tests
│
├── run_review.py              # Submit + poll script
├── requirements.txt
├── .env.example
└── EVALUATION.md              # Real benchmark numbers after testing
```

---

## 🔐 Environment Variables

```env
# Required
GROQ_API_KEY=your_groq_api_key          # console.groq.com (free)
GITHUB_TOKEN=your_github_token           # Fine-grained, repo read + PR write
GITHUB_WEBHOOK_SECRET=your_secret        # openssl rand -hex 32

# Optional
USE_FINETUNED_MODEL=false                # true after running finetuning/train.py
CODEBERT_MODEL_PATH=data/models/codebert-vulnerability-detector
REPORT_OUTPUT_DIR=data/reports
LOG_LEVEL=INFO
```

---

<div align="center">

**Built with LangGraph · Groq · Bandit · Semgrep · CodeBERT · FastAPI · React**

*Final Year Project — B.E. Artificial Intelligence & Machine Learning — 2026*

</div>