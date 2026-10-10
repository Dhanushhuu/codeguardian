# CodeGuardian

A multi-agent code review system that scans Python and JavaScript/TypeScript for security and quality issues, triages the findings with an LLM, proposes fixes, and reports back through a web UI, GitHub pull-request comments, and a PDF audit report.

![LangGraph](https://img.shields.io/badge/Orchestration-LangGraph-blue) ![FastAPI](https://img.shields.io/badge/API-FastAPI-green) ![License](https://img.shields.io/badge/License-MIT-lightgrey)

> **Status.** This is a student project built to learn and demonstrate multi-agent system design. The detection layers have been measured on a small labelled benchmark (see [Results](#results)); some components have not been evaluated yet (see [Component status](#component-status)). Read [EVALUATION.md](EVALUATION.md) before drawing conclusions about accuracy.

---

## How it works

```
Source files / PR diff
        │
        ▼
     Parser
        │
        ▼   LangGraph fan-out (parallel)
   ┌────┴─────────────┐
   ▼                  ▼
Security agent    Quality agent
   │
   │  files processed concurrently
   │  (ThreadPoolExecutor, 4 workers)
   │  per file, in order:  Bandit → Semgrep → CodeBERT (optional)
   ▼
LLM triage (LLaMA 3.3 70B via Groq) → Fix agent → Report / PR comment / PDF
```
<!-- VERIFY: confirm the order of stages after the fan-out (triage, fix, test generation, report) against the LangGraph definition. -->

Key design points:

- **Parallelism is at two levels.** After parsing, LangGraph runs the Security and Quality agents in parallel. Inside the Security agent, a thread pool processes multiple files concurrently. The detection layers themselves (Bandit, Semgrep, CodeBERT) run **sequentially** on each file.
- **Rule-based tools carry the findings.** Bandit and Semgrep provide the precision-oriented results.
- **LLM triage** (LLaMA 3.3 70B on Groq) reviews findings, explains exploitability, and can flag additional issues.
- **Fix agent** generates category-specific fixes (for example SQL injection to parameterized queries, hardcoded secrets to environment variables) and checks that each patch still parses with Python's `ast` module.
- **GitHub integration:** webhook intake, PR review comments, and a PDF audit report.

---

## Component status

| Component | Status |
|---|---|
| Bandit + Semgrep detection | Implemented; measured on a 48-snippet Python benchmark ([results](#results)) |
| CodeBERT classifier | Fine-tuned and measured; **shown not to transfer to Python**, so it is off by default ([details](#codebert-classifier)) |
| LLM triage | Implemented; **not yet evaluated** (no measured false-positive dismissal rate; not tested against prompt injection in code comments) |
| Fix agent | Implemented; patches are checked for **syntax only** (`ast.parse`); re-scanning patched code is not yet part of the pipeline |
| Test generation (pytest / jest) | Implemented; **not yet evaluated** |
| GitHub webhook, PR comments, PDF report | Implemented |
| Quality agent | Implemented; not part of the evaluation so far |
<!-- VERIFY: confirm each "Implemented" line against the code and a working demo before publishing. -->

---

## Results

On a hand-written benchmark of **48 Python snippets** (24 vulnerable, 24 matched safe versions), all severities reported:

| Configuration | Precision | Recall | False-positive rate |
|---|---|---|---|
| Bandit only | 85% | 71% | 12% |
| Bandit + Semgrep | 86% | 75% | 12% |
| Bandit + Semgrep + CodeBERT | 50% | 100% | 100% |
| CodeBERT alone | 50% | 100% | 100% |

- Bandit and Semgrep catch all 17 pattern-style cases (SQL injection, `shell=True`, pickle and similar) but almost none of the 7 semantic ones (missing authorization, IDOR, SSRF and similar): 0 of 7 for Bandit, 1 of 7 with Semgrep added.
- CodeBERT flagged **every** snippet, so adding it made the ensemble worse.
- The benchmark is small and hand-written, and it favours rule-based tools on pattern-style cases. Treat it as a smoke test, not a benchmark. Full tables, confidence intervals, and caveats are in [EVALUATION.md](EVALUATION.md).
- The end-to-end pipeline (including LLM triage and fixes) has **not** been scored yet; those cells are marked TBD in [EVALUATION.md](EVALUATION.md).

---

## CodeBERT classifier

CodeBERT was fine-tuned as a binary vulnerability classifier on CodeXGLUE Defect Detection (Devign: 21,854 training functions, **written in C**).

| Item | Value |
|---|---|
| Setup | 3 epochs, batch size 8, learning rate 2e-5, max length 512, fp16, seed 42 |
| Model selection | Best checkpoint by validation F1; the test set was evaluated once at the end |
| Test accuracy | 61.5% (majority-class baseline 54.1%) |
| Test F1 / precision / recall | 0.578 / 0.582 / 0.574 |
| Script | [`finetuning/train_codebert_fixed.py`](finetuning/train_codebert_fixed.py) |
| Raw results | [`finetuning/results/eval_results.json`](finetuning/results/eval_results.json) |

These C-language figures are in line with commonly reported CodeBERT results on this noisy benchmark: a weak signal, about 7 points above always guessing "safe".

**Transfer to Python.** Because CodeGuardian scans Python and JS/TS, the model was also tested on the Python benchmark above. It assigned P(vulnerable) ≈ 0.998 to every snippet (ROC-AUC 0.544, false-positive rate 100%). Two control experiments confirm this is a domain effect and not a bug: on 300 Devign test functions (C) the same inference code gives 63.7% accuracy and flags 46% of functions, while on 148 long, real Python standard-library functions it returns 0.998 for every single one. It is therefore **not counted as a detector** and is disabled by default.
<!-- VERIFY: make sure USE_FINETUNED_MODEL defaults to false in the code and that CodeBERT output is excluded from reported findings when it is off. -->

The weights (~500 MB) are not stored in this repository. To reproduce them, run the training script (about 35–40 minutes on a Colab T4) and place the output folder at `data/models/codebert-vulnerability-detector`. To experiment with it:

```bash
USE_FINETUNED_MODEL=true
```

**Planned:** fine-tune on a Python vulnerability dataset with project-level train/test splits and re-run the same benchmark.

---

## Quick start

```bash
git clone https://github.com/Dhanushhuu/codeguardian.git
cd codeguardian
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # then fill in your keys
```

Minimum configuration in `.env`:

```bash
GROQ_API_KEY=<your Groq API key>
USE_FINETUNED_MODEL=false         # keep off: CodeBERT does not transfer to Python
```
<!-- VERIFY: confirm .env.example exists and document the other variables (GitHub token, webhook secret, ...) with their real names. -->

### Start the API

```bash
# Start the API server
uvicorn api.main:app --reload --port 8000

# In a new terminal: run a review
python run_review.py

# Interactive API docs (Swagger UI)
# http://localhost:8000/docs
```

### Start the frontend

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

Notes: Semgrep's native Windows support is limited, so Linux, macOS, or WSL is recommended. Code submitted for review is sent to a third-party LLM provider (Groq); do not submit proprietary code you are not allowed to share.

---

## Reproducing the evaluation

See [EVALUATION.md, section 5](EVALUATION.md#5-reproducing-these-results). In short:

```bash
python evaluation/eval_ablation.py --model-dir <path to CodeBERT folder> --out evaluation/results
python evaluation/codebert_controls.py --model-dir <path to CodeBERT folder>
```

---

## Known limitations

- The Python benchmark is small (48 snippets), hand-written, and not representative of real repositories; there is no JS/TS evaluation yet.
- Rule-based tools miss semantic flaws (authorization, IDOR, SSRF and similar). No component has been shown to catch them reliably.
- LLM triage is unevaluated. It reads untrusted code, so prompt injection through code comments is a risk that has not been tested.
- Fixes are validated for syntax only, not for whether they remove the finding.
- Findings reported by several layers for the same line may be duplicated in the output.
- CodeBERT does not transfer from C to Python (see above).
- Generated tests have not been evaluated.

## Roadmap

1. Score the full pipeline (LLM triage, fixes, test generation) on the labelled benchmark and fill the TBD cells in `EVALUATION.md`.
2. De-duplicate findings by file, line, and weakness type; recalibrate severities.
3. Re-scan patched code after each fix and report how many fixes actually clear the finding.
4. Test the LLM triage against prompt injection; never let it suppress high-severity findings on its own.
5. Fine-tune a Python-capable classifier with project-level splits and re-run the benchmark.
6. Add CI and unit tests for each agent; pin dependency versions.

---

## Repository layout (files added by the evaluation work)

```
├── README.md
├── EVALUATION.md
├── evaluation/
│   ├── eval_ablation.py          # ablation + Python-transfer harness
│   ├── codebert_controls.py      # control experiments for the transfer result
│   └── results/                  # results.json / results.md from the runs
├── finetuning/
│   ├── train_codebert_fixed.py
│   └── results/eval_results.json
└── ...                           # existing application code
```

## Author

**Dhanush Kumar**. B.E. Artificial Intelligence & Machine Learning, G. Pulla Reddy Engineering College. GitHub: [Dhanushhuu](https://github.com/Dhanushhuu)

## License

MIT (add a `LICENSE` file to the repository).
