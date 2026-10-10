# CodeGuardian — Evaluation

This document records what has been **measured** and what has **not**. Numbers appear only where they come from a run whose output is saved in the repo. Cells marked _TBD_ have not been measured yet.

---

## 1. CodeBERT vulnerability classifier

### Setup

| Item | Value |
|---|---|
| Base model | `microsoft/codebert-base` (125M parameters, RoBERTa architecture) |
| Task | Binary classification of a function: vulnerable vs. not vulnerable |
| Dataset | CodeXGLUE Defect Detection (Devign), `google/code_x_glue_cc_defect_detection` |
| Language of training data | C functions |
| Split sizes | Train 21,854 · Validation 2,732 · Test 2,732 |
| Test class balance | 45.9% vulnerable (1,255 of 2,732) |
| Epochs | 3 |
| Batch size | 8 |
| Learning rate | 2e-5 (warmup 200 steps, weight decay 0.01) |
| Max sequence length | 512 tokens (longer functions are truncated) |
| Numeric precision | fp16 on a Colab GPU |
| Seed | 42 |
| Model selection | Best checkpoint by **validation** F1 (`load_best_model_at_end`) |
| Test set usage | Evaluated once, after training |
| Training script | `finetuning/train_codebert_fixed.py` |
| Raw results | `finetuning/results/eval_results.json` |

### Results

| Metric | Validation | **Test** |
|---|---|---|
| Accuracy | 61.35% | **61.46%** |
| F1 (vulnerable class) | 0.5658 | **0.5776** |
| Precision | 0.5526 | **0.5816** |
| Recall | 0.5796 | **0.5737** |
| Validation loss | 0.6100 | — |

**Majority-class baseline** (always predict "not vulnerable"): 54.06% accuracy on the test set.

**Test confusion matrix**

|  | Predicted safe | Predicted vulnerable |
|---|---|---|
| **Actually safe** | 959 (TN) | 518 (FP) |
| **Actually vulnerable** | 535 (FN) | 720 (TP) |

### Interpretation

- Accuracy is **7.4 points above the majority baseline**. The 95% margin of error on a test set of 2,732 samples is about ±1.8 points.
- When the model flags a function as vulnerable, it is right 58% of the time, against a 46% base rate (about 1.27× lift over guessing by prevalence).
- It misses **42.6%** of vulnerable functions (535 of 1,255) and falsely flags **35.1%** of safe functions (518 of 1,477).
- These results are in line with figures commonly reported for CodeBERT on this benchmark (roughly 62% accuracy). The benchmark is noisy and difficult, so this should be read as a weak signal, not a reliable detector.
- Training loss at the end was 0.540 against a validation loss of 0.610, a mild generalisation gap.

### Caveats

- **Domain mismatch (now measured, see §3).** The model was trained on C functions, while CodeGuardian analyses Python and JavaScript/TypeScript. On a small Python benchmark it flagged every snippet, so it carries no usable signal there.
- **Truncation.** Functions over 512 tokens are truncated, so late parts of long functions are not seen.
- **Label noise.** Devign labels come from commit history and are known to be noisy, which limits achievable accuracy.
- **Single run.** One seed, one configuration, no hyperparameter search.

### Role in the pipeline

Because the classifier gave the same near-certain "vulnerable" score to every Python snippet and function tested (§3), it is **not counted as a detector for Python code**. The recommended configuration is `USE_FINETUNED_MODEL=false` by default, with the model available only for informational output.
<!-- VERIFY: make the code match this (default off, or CodeBERT output excluded from the reported findings), then keep this paragraph. -->

---

## 2. End-to-end pipeline on the sample file

A sample Python file with deliberately planted vulnerabilities was used for demonstration. Earlier documentation reported inconsistent counts (8/8 and 9/9), so those figures are **withdrawn** until the run is repeated and recorded here.

| Item | Result |
|---|---|
| Planted vulnerabilities | _TBD_ |
| Detected by the pipeline (after de-duplication) | _TBD_ |
| Total findings before de-duplication | _TBD_ |
| Findings after de-duplication | _TBD_ |
| False positives dismissed by the LLM filter | _TBD_ |
| Fixes generated / fixes passing `ast.parse` | _TBD_ |
| Fixes that clear the finding when re-scanned | _TBD_ |
| Test files generated / passing | _TBD_ |
| End-to-end latency (median of 5 runs) | _TBD_ |

Note: one planted file with a handful of bugs, written by the author, is a demonstration, not a benchmark.

---

## 3. Ablation and Python-transfer test (measured)

**Benchmark.** 48 hand-written Python snippets: 24 vulnerable and 24 matched safe versions. Seventeen pairs are well-known dangerous patterns (SQL injection, `shell=True`, pickle, `yaml.load`, weak hashing and similar). Seven pairs are semantic flaws with no single dangerous call (missing authorization, IDOR, path traversal, open redirect, SSRF, JWT without verification, timing-unsafe comparison). Harness: `evaluation/eval_ablation.py`. Raw output: `evaluation/results/results.json`.
Unit of evaluation: a configuration flags a snippet if any of its layers reports a finding. Semgrep ruleset: `p/python`. CodeBERT threshold: P(vulnerable) ≥ 0.5.
Tool versions: _TBD (record `bandit --version` and `semgrep --version`)_.

### Results, all severities reported

| Configuration | Precision | Recall | False-positive rate | TP/FP/FN/TN |
|---|---|---|---|---|
| Bandit only | 85% (17/20) | 71% (17/24; CI 51–85%) | 12% (3/24; CI 4–31%) | 17/3/7/21 |
| Bandit + Semgrep | 86% (18/21) | 75% (18/24; CI 55–88%) | 12% (3/24; CI 4–31%) | 18/3/6/21 |
| Bandit + Semgrep + CodeBERT | 50% (24/48) | 100% (24/24) | **100%** (24/24; CI 86–100%) | 24/24/0/0 |
| CodeBERT alone (C → Python) | 50% (24/48) | 100% (24/24) | **100%** (24/24; CI 86–100%) | 24/24/0/0 |

### Results, MEDIUM severity and above

| Configuration | Precision | Recall | False-positive rate | TP/FP/FN/TN |
|---|---|---|---|---|
| Bandit only | 94% (15/16) | 62% (15/24) | 4% (1/24) | 15/1/9/23 |
| Bandit + Semgrep | 94% (16/17) | 67% (16/24) | 4% (1/24) | 16/1/8/23 |
| Bandit + Semgrep + CodeBERT | 50% (24/48) | 100% (24/24) | 100% (24/24) | 24/24/0/0 |
| CodeBERT alone (C → Python) | 50% (24/48) | 100% (24/24) | 100% (24/24) | 24/24/0/0 |

### Recall by weakness type (all severities)

| Configuration | Pattern-style (17) | Semantic (7) |
|---|---|---|
| Bandit only | 100% | 0% (0/7) |
| Bandit + Semgrep | 100% | 14% (1/7) |
| Bandit + Semgrep + CodeBERT | 100% | 100% (7/7; constant prediction, see Findings) |
| CodeBERT alone | 100% | 100% (7/7; constant prediction, see Findings) |

### CodeBERT transfer diagnostics

- ROC-AUC on the benchmark: **0.544** (0.5 = chance).
- Mean P(vulnerable): vulnerable snippets **0.998**, safe snippets **0.998**.
- It flagged **48 of 48** snippets.

### Findings

1. **Bandit and Semgrep behave as expected.** They catch every pattern-style case (at all severities) and almost none of the semantic cases (0/7 and 1/7). Semgrep `p/python` added one true positive and no false positives over Bandit alone.
2. **CodeBERT shows no usable signal on Python.** It assigns about the same near-certain "vulnerable" probability to safe and vulnerable code. Its 100% recall, including on the semantic cases, is just a constant "vulnerable" prediction and not detection ability. Adding it to the ensemble raises the false-positive rate from 12% to 100% and drops precision from 86% to 50%.
3. **The semantic cases are where an ML layer could help**, because rules miss them, but this model cannot separate them from safe code.
4. **Controls confirm the result is a domain effect** (see Control experiments): the model is well-behaved on C and gives one constant score on every Python function tested.

### Control experiments

Run with `evaluation/codebert_controls.py` to check that the saturation is a real domain effect and not an evaluation bug or a short-snippet artefact.

| Control | Input | Result |
|---|---|---|
| 1. Inference sanity check | 300 random Devign test functions (C), same inference code | Accuracy **63.7%** (full-test: 61.5%); **46.3%** flagged (45.9% expected); mean P(vulnerable) 0.589 for vulnerable vs 0.442 for safe functions |
| 2. Long Python functions | 148 real Python standard-library functions (median 752 chars, versus 983 for the C sample), not security-related and presumed benign | **100% flagged**; P(vulnerable) = **0.998 for every function** (minimum equals maximum) |

- **Control 1** shows the model loads and runs correctly: on C it behaves as in training (about 46% flagged, accuracy within sampling error of the full test set; the 95% margin on 300 samples is about ±5 points). So the Python result is not an evaluation bug.
- **Control 2** shows the saturation is not caused by very short snippets: long Python functions of similar length to the C sample get the same constant score. On Python input the model's output carries no information. The stdlib functions were not individually labelled, but that does not affect the conclusion, because the score is identical for all of them.
- **Likely cause (hypothesis, not tested):** surface-form differences between C and Python (syntax, indentation, token statistics) push inputs far outside the training distribution.

### Limits

- **Small, hand-written benchmark.** 24 per class gives wide confidence intervals, and the pattern-style cases favour rule-based tools. With n = 48, an AUC of 0.544 cannot be distinguished from 0.5 on its own; the constant score on Python (Control 2) is the stronger evidence.
- Snippet-level scoring ignores which weakness was reported.
- **Full pipeline (with LLM triage) row:** not measured yet; requires implementing the `pipeline_flag` hook in `evaluation/eval_ablation.py`. _TBD._

---

## 4. Known evaluation gaps

- The Python benchmark is small and hand-written (48 snippets), and there is no JavaScript/TypeScript evaluation yet.
- The LLM false-positive filter has not been shown dismissing a real false positive, and has not been tested against prompt injection in code comments.
- Generated fixes are validated only for syntax; re-scanning and running generated tests are not yet part of the evaluation.
- No baseline measurement for the claimed speed-up from parallel execution.

---

## 5. Reproducing these results

All commands were designed for Google Colab (Linux). Semgrep's native Windows support is limited.

```bash
pip install -q bandit semgrep transformers torch datasets scikit-learn accelerate

# 1. Fine-tune CodeBERT (about 35-40 min on a T4); writes eval_results.json next to the model
#    (edit OUTPUT_DIR inside the script if you do not use Google Drive)
python finetuning/train_codebert_fixed.py

# 2. Ablation + Python-transfer test (needs the model folder from step 1)
python evaluation/eval_ablation.py \
    --model-dir /path/to/codebert-vulnerability-detector \
    --out evaluation/results

# 3. Controls: is the Python saturation a domain effect or an evaluation bug?
python evaluation/codebert_controls.py --model-dir /path/to/codebert-vulnerability-detector
```

Use `--primary "MEDIUM and above"` in step 2 if your pipeline only reports medium-and-above findings, and `--extra-jsonl` to add a larger Python set (one `{"id","code","label"}` per line). Record `bandit --version` and `semgrep --version` alongside the results, since rule sets change between versions.
