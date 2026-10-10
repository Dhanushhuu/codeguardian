<div align="center">

# 🛡️ CodeGuardian

### Multi-agent code security & quality review

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-FF6B35?style=for-the-badge&logo=langchain&logoColor=white)](https://langchain.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

Built by **Dhanush Kumar** · Final-year B.E. (AI & ML) · 2026

</div>

> **Status.** A student project built to learn and demonstrate multi-agent system design. The detection layers were measured on a small labelled Python benchmark (see [Results](#results)); several components have not been evaluated yet (see [Component status](#component-status)). Read [EVALUATION.md](EVALUATION.md) before drawing conclusions about accuracy.

---

## Table of contents

[What it does](#what-it-does) · [How it works](#how-it-works) · [Detection layers](#detection-layers) · [Component status](#component-status) · [Results](#results) · [CodeBERT classifier](#codebert-classifier) · [Quick start](#quick-start) · [API reference](#api-reference) · [Tech stack](#tech-stack) · [Project structure](#project-structure) · [Environment variables](#environment-variables) · [Reproducing the evaluation](#reproducing-the-evaluation) · [Known limitations](#known-limitations) · [Roadmap](#roadmap)

---

## What it does

CodeGuardian reviews code submitted manually through the API or UI, or arriving as a GitHub pull request via webhook. It:

1. **Parses** the code into files and function-level units (Python and JavaScript/TypeScript).
2. **Scans** each file with Bandit, Semgrep and (optionally) a CodeBERT classifier, then has an **LLM review the findings**: dismiss false positives with an explanation, add exploitation context, and flag additional issues.
3. **Reviews quality** in parallel with Radon complexity metrics, AST checks and an LLM quality review.
4. **Generates fixes** from category-specific templates and checks that each patch still parses.
5. **Writes tests** (pytest for Python, jest for JS/TS).
6. **Reports** a verdict as a structured GitHub PR comment and a PDF audit report.

---

## How it works

```
        GitHub PR (webhook)  or  POST /review
                       │
                       ▼
        ┌──────────────────────────────┐
        │         PARSER AGENT         │
        │ language detection · AST     │
        │ function-level code units    │
        └──────────────┬───────────────┘
                       │
             LangGraph fan-out (parallel)
              ┌────────┴─────────┐
              ▼                  ▼
   ┌────────────────────┐  ┌──────────────────┐
   │   SECURITY AGENT   │  │  QUALITY AGENT   │
   │ files scanned      │  │ Radon CC / MI    │
   │ concurrently       │  │ AST checks       │
   │ (thread pool, 4)   │  │ LLM quality      │
   │ per file, in order:│  │ review           │
   │  Bandit → Semgrep  │  └────────┬─────────┘
   │  → CodeBERT (opt.) │           │
   │ then LLM review of │           │
   │ the findings       │           │
   └─────────┬──────────┘           │
             └────────┬─────────────┘
                      │ merged results (fan-in)
                      ▼
        ┌──────────────────────────────┐
        │          FIX AGENT           │
        │ category-specific templates  │
        │ ast.parse() syntax check     │
        └──────────────┬───────────────┘
                       ▼
        ┌──────────────────────────────┐
        │      TEST WRITER AGENT       │
        │ pytest (Python) · jest (JS)  │
        └──────────────┬───────────────┘
                       ▼
        ┌──────────────────────────────┐
        │        REVIEWER AGENT        │
        │ verdict · GitHub PR comment  │
        │ PDF report                   │
        └──────────────────────────────┘
```

**Parallelism, precisely.** After parsing, LangGraph runs the Security and Quality agents in parallel. Inside the Security agent, a `ThreadPoolExecutor` (4 workers) processes several files concurrently, while Bandit, Semgrep and CodeBERT are applied **sequentially** to each individual file (`_scan_file()`).

---

## Detection layers

| # | Layer | Tool | What it covers |
|---|---|---|---|
| 1 | Static analysis | Bandit | Python checks with CWE mapping: SQL injection, shell injection, hardcoded passwords, weak crypto, insecure deserialization, and more |
| 2 | Pattern matching | Semgrep | Community rules for Python, JavaScript and TypeScript; custom YAML rules supported |
| 3 | ML classifier (optional, off by default) | CodeBERT | Function-level binary classifier fine-tuned on CodeXGLUE Defect Detection (Devign, C code). **Measured not to transfer to Python**, see [below](#codebert-classifier) |
| 4 | LLM review | LLaMA 3.3 70B (Groq) | Reviews the scanner findings, can dismiss false positives with an explanation, adds exploitation context, and can flag issues the scanners did not report |

Bandit and Semgrep carry the findings. See [Results](#results) for what each layer was measured to add.

---

## Component status

| Component | Status |
|---|---|
| Parser agent | Implemented |
| Bandit + Semgrep detection | Implemented; measured on a 48-snippet Python benchmark |
| CodeBERT classifier | Fine-tuned and measured; **does not transfer to Python**, so it is off by default |
| LLM review of findings (in the Security agent) | Implemented; **not yet evaluated**: no measured false-positive dismissal rate, and not tested against prompt injection in code comments |
| Quality agent | Implemented; not part of the evaluation so far |
| Fix agent | Implemented; patches are checked for **syntax only** (`ast.parse`); re-scanning patched code is not part of the pipeline yet |
| Test Writer agent | Implemented; **not yet evaluated** (a demo run reported 0 generated test files) |
| Reviewer agent: verdict, PR comment, PDF report | Implemented |
| GitHub webhook intake | Implemented |
<!-- VERIFY: confirm each "Implemented" line against the code and a working demo before publishing. -->

---

## Results

### Ablation on a labelled Python benchmark

48 hand-written Python snippets: 24 vulnerable and 24 matched safe versions. All severities reported:

| Configuration | Precision | Recall | False-positive rate |
|---|---|---|---|
| Bandit only | 85% | 71% | 12% |
| Bandit + Semgrep | 86% | 75% | 12% |
| Bandit + Semgrep + CodeBERT | 50% | 100% | 100% |
| CodeBERT alone | 50% | 100% | 100% |

- Bandit and Semgrep catch all 17 pattern-style cases (SQL injection, `shell=True`, pickle and similar) but almost none of the 7 semantic ones (missing authorization, IDOR, SSRF and similar): 0 of 7 for Bandit, 1 of 7 with Semgrep added.
- CodeBERT flagged **every** snippet, so adding it made the ensemble worse.
- The benchmark is small and hand-written, and it favours rule-based tools on pattern-style cases. It is a smoke test, not a benchmark. Full tables, confidence intervals and caveats are in [EVALUATION.md](EVALUATION.md).
- The full pipeline (LLM review, fixes, test generation) has **not** been scored yet; those cells are marked TBD in [EVALUATION.md](EVALUATION.md).

### Demo run

A demo run on `data/samples/vulnerable_example.py` (a file with deliberately planted vulnerabilities) reported 24 security findings and 18 quality findings, generated 10 fixes (9 of 10 passed `ast.parse()`), dismissed 0 false positives, and generated 0 test files. The same line is often reported by more than one layer (for example the `shell=True` call at line 24), so the finding count overstates the number of distinct issues. This is a demonstration, not a measurement. Counts of "planted vulnerabilities detected" and timings from earlier documentation have been withdrawn until they are re-measured.
<!-- VERIFY: confirm this demo run used the default configuration (USE_FINETUNED_MODEL=false) and check what the CodeBERT layer does in that mode. If the "codebert" findings in the sample came from heuristic rules instead of the model, say so here and rename the layer in the report. -->

---

## CodeBERT classifier

CodeBERT was fine-tuned as a binary vulnerability classifier on CodeXGLUE Defect Detection (Devign: 21,854 training functions, **written in C**).

| Item | Value |
|---|---|
| Setup | Full fine-tuning, 3 epochs, batch size 8, learning rate 2e-5, max length 512, fp16, seed 42 |
| Model selection | Best checkpoint by validation F1; the test set was evaluated once at the end |
| Test accuracy | 61.5% (majority-class baseline 54.1%) |
| Test F1 / precision / recall | 0.578 / 0.582 / 0.574 |
| Script | [`finetuning/train_codebert_fixed.py`](finetuning/train_codebert_fixed.py) |
| Raw results | [`finetuning/results/eval_results.json`](finetuning/results/eval_results.json) |
<!-- VERIFY: finetuning/train.py in this repo is a LoRA script and is NOT what produced these numbers. Either delete it or replace it with train_codebert_fixed.py; if you keep it, add peft to requirements.txt and document it separately. -->

These C-language figures are in line with commonly reported CodeBERT results on this noisy benchmark: a weak signal, about 7 points above always guessing "safe".

**Transfer to Python.** On the Python benchmark above, the model assigned P(vulnerable) ≈ 0.998 to every snippet (ROC-AUC 0.544, false-positive rate 100%). Two control experiments confirm this is a domain effect and not a bug: on 300 Devign test functions (C) the same inference code gives 63.7% accuracy and flags 46% of functions, while on 148 long, real Python standard-library functions it returns 0.998 for every one. The model is therefore **not counted as a detector** and is off by default (`USE_FINETUNED_MODEL=false`).
<!-- VERIFY: make sure the code actually excludes CodeBERT output from the reported findings when USE_FINETUNED_MODEL=false. -->

The weights (~500 MB) are not stored in this repository. To reproduce them, run the training script (about 35–40 minutes on a Colab T4) and place the output folder at the path in `CODEBERT_MODEL_PATH`.

**Planned:** fine-tune on a Python vulnerability dataset with project-level train/test splits and re-run the same benchmark.

---

## Quick start

### Prerequisites

- Python 3.10+
- Node.js 18+ (frontend only)
- A [Groq API key](https://console.groq.com) (free tier; subject to rate limits)
- A [GitHub token](https://github.com/settings/tokens) (only for PR comments and webhooks)

### Setup

```bash
git clone https://github.com/Dhanushhuu/codeguardian
cd codeguardian

python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env              # then add GROQ_API_KEY and GITHUB_TOKEN
```

### Run the API

```bash
# Start the API server
uvicorn api.main:app --reload --port 8000

# In a new terminal: run a review
python run_review.py

# Interactive API docs (Swagger UI)
# http://localhost:8000/docs
```

`run_review.py` submits `data/samples/vulnerable_example.py`, polls for the result, and saves the full report to `review_result.json`.

### Run the frontend

```bash
cd frontend
npm install
npm run dev
# Open http://localhost:5173
```

### Run the tests

```bash
# Tool-level tests (no API key needed)
python tests/test_pipeline.py --tools-only

# Full pipeline test (needs GROQ_API_KEY)
python tests/test_pipeline.py
```

**Notes.** Semgrep's native Windows support is limited, so Linux, macOS or WSL is recommended. Code submitted for review is sent to a third-party LLM provider (Groq); do not submit proprietary code you are not allowed to share.

---

## API reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Health check |
| `POST` | `/review` | Submit code for manual review |
| `GET` | `/status/{id}` | Job status and live event log |
| `GET` | `/stream/{id}` | SSE stream of agent activity |
| `GET` | `/results/{id}` | Full JSON report |
| `GET` | `/results/{id}/pdf` | Download the PDF report |
| `POST` | `/webhook/github` | GitHub pull-request webhook receiver |

---

## Tech stack

| Component | Technology |
|---|---|
| Agent framework | LangGraph (parallel fan-out, shared state) |
| LLM | Groq, LLaMA 3.3 70B |
| Python security | Bandit |
| Multi-language security | Semgrep |
| ML classifier | CodeBERT (`microsoft/codebert-base`), Hugging Face Transformers, PyTorch |
| Code quality | Radon (cyclomatic complexity, maintainability index) |
| GitHub integration | PyGithub, webhooks |
| PDF reports | ReportLab |
| Backend | FastAPI with server-sent events |
| Frontend | React, Vite |

The default setup uses free tiers (Groq, GitHub), so it has no required paid services; free-tier rate limits apply.

---

## Project structure

```
codeguardian/
├── agents/
│   ├── parser_agent.py         # File parsing and function-level AST extraction
│   ├── security_agent.py       # Concurrent per-file scan + LLM review of findings
│   ├── quality_agent.py        # Radon + AST + LLM quality review
│   ├── fix_agent.py            # Template-guided fixes + ast.parse() check
│   ├── test_writer_agent.py    # pytest / jest generation
│   └── reviewer_agent.py       # Verdict, GitHub PR comment, PDF report
├── tools/
│   ├── pr_parser.py            # Language detection + function extraction
│   ├── bandit_scanner.py       # Bandit with CWE / OWASP mapping
│   ├── semgrep_scanner.py      # Multi-language Semgrep integration
│   ├── codebert_classifier.py  # CodeBERT inference
│   └── quality_analyzer.py     # Radon + AST quality checks
├── graph/
│   ├── state.py                # ReviewState (annotated for parallel nodes)
│   └── pipeline.py             # LangGraph graph: fan-out and fan-in
├── api/
│   └── main.py                 # FastAPI, webhook, SSE, PDF download
├── frontend/
│   └── src/App.jsx             # React dashboard with live agent log
├── finetuning/
│   ├── train_codebert_fixed.py # Training script behind the reported results
│   └── results/eval_results.json
├── evaluation/
│   ├── eval_ablation.py        # Ablation + Python-transfer harness
│   ├── codebert_controls.py    # Control experiments for the transfer result
│   └── results/                # results.json / results.md from the runs
├── data/samples/
│   └── vulnerable_example.py   # Sample file with planted vulnerabilities
├── tests/
│   └── test_pipeline.py        # Tool-level and integration tests
├── run_review.py               # Submit + poll script
├── requirements.txt
├── .env.example
├── EVALUATION.md
└── README.md
```

---

## Environment variables

```env
# Required
GROQ_API_KEY=your_groq_api_key           # console.groq.com
GITHUB_TOKEN=your_github_token           # fine-grained: repo read + PR write
GITHUB_WEBHOOK_SECRET=your_secret        # e.g. openssl rand -hex 32

# Optional
USE_FINETUNED_MODEL=false                # keep false: CodeBERT does not transfer to Python
CODEBERT_MODEL_PATH=data/models/codebert-vulnerability-detector
REPORT_OUTPUT_DIR=data/reports
LOG_LEVEL=INFO
```

---

## Reproducing the evaluation

See [EVALUATION.md, section 5](EVALUATION.md#5-reproducing-these-results). In short:

```bash
python evaluation/eval_ablation.py --model-dir <path to CodeBERT folder> --out evaluation/results
python evaluation/codebert_controls.py --model-dir <path to CodeBERT folder>
```

---

## Known limitations

- The Python benchmark is small (48 snippets), hand-written and not representative of real repositories; there is no JS/TS evaluation yet.
- Rule-based tools miss semantic flaws (authorization, IDOR, SSRF and similar), and no component has been shown to catch them reliably.
- The LLM review step is unevaluated. It reads untrusted code, so prompt injection through code comments is a risk that has not been tested.
- Fixes are validated for syntax only, not for whether they remove the finding.
- The same issue reported by several layers may appear more than once in the output.
- CodeBERT does not transfer from C to Python (see above).
- Generated tests have not been evaluated.
- Job state is held by the API process; it is not designed for multiple workers or persistence across restarts.
<!-- VERIFY: confirm the last point (in-memory job state) against api/main.py, or remove it. -->

## Roadmap

1. Score the full pipeline (LLM review, fixes, test generation) on the labelled benchmark and fill the TBD cells in `EVALUATION.md`.
2. De-duplicate findings by file, line and weakness type; recalibrate severities.
3. Re-scan patched code after each fix and report how many fixes actually clear the finding.
4. Test the LLM review step against prompt injection; never let it suppress high-severity findings on its own.
5. Fine-tune a Python-capable classifier with project-level splits and re-run the benchmark.
6. Add CI, per-agent unit tests, and pinned dependency versions.

---

<div align="center">

**Built with LangGraph · Groq · Bandit · Semgrep · CodeBERT · FastAPI · React**

*Final-year project, B.E. Artificial Intelligence & Machine Learning, 2026*

</div>
