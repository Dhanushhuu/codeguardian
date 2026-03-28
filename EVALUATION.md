# CodeGuardian — Evaluation Results

> **Rule**: Fill every `[FILL]` with REAL numbers from your actual test run.
> Never paste target numbers. Run the tests, record what you get.

---
## 1. System Performance
Average end-to-end review time: ~45s   ← from your run
Speedup from parallelism: ~2x

## 2. Security Detection
Bandit:   11 issues
Semgrep:   3 issues  
CodeBERT:  7 issues
LLM:       3 issues
Total:    24 issues

Detection rate: 8/8 vulnerabilities = 100%

## Severity Breakdown
Critical: 0
High:    13
Medium:   7
Low:      4


## 3. CodeBERT Fine-Tuning Results

Dataset: [CodeXGLUE Defect Detection](https://github.com/microsoft/CodeXGLUE/tree/main/Code-Code/Defect-detection) (Devign)

> Numbers from `data/models/codebert-vulnerability-detector/eval_results.json`

| Metric | Base Model (heuristics) | Fine-Tuned Model |
|---|---|---|
| F1 Score | [FILL] | [FILL] |
| Accuracy | [FILL] | [FILL] |
| Precision | [FILL] | [FILL] |
| Recall | [FILL] | [FILL] |

Training config:
- Epochs: 3
- Batch size: 8
- Learning rate: 2e-5
- Max sequence length: 512
- GPU: [FILL] (e.g. T4 on Colab)
- Training time: [FILL] min

---

## 4. Fix Generation Quality

| Metric | Value |
|---|---|
| Fixes generated (sample run) | [FILL] |
| Fixes passing `ast.parse()` | [FILL] / [FILL] ([FILL]%) |
| Fix categories covered | [FILL] |

---

## 5. Test Generation

| Metric | Value |
|---|---|
| Test files generated | [FILL] |
| Framework used | pytest |
| Functions covered | [FILL] |
| Tests that pass without modification | [FILL] / [FILL] |

---

## 6. LLM False Positive Filtering

| Metric | Value |
|---|---|
| Raw scanner issues | [FILL] |
| Dismissed as FP by LLM | [FILL] |
| Final issues after filtering | [FILL] |
| FP dismissal rate | [FILL]% |

---

## 7. Comparison vs Alternatives

| Feature | GitHub Copilot | SonarQube | **CodeGuardian** |
|---|---|---|---|
| Multi-layer detection | ❌ | Partial | ✅ Bandit + Semgrep + CodeBERT |
| Fine-tuned ML classifier | ❌ | ❌ | ✅ CodeBERT on CodeXGLUE |
| Auto-generated fixes | ❌ | ❌ | ✅ With syntax validation |
| Auto-generated tests | ❌ | ❌ | ✅ pytest + jest |
| LLM FP filtering | ❌ | ❌ | ✅ Dismisses FPs with reason |
| Parallel agent execution | ❌ | ❌ | ✅ LangGraph fan-out |
| Total cost | Paid | Paid | **$0** |

---

## 8. Interview One-Liner

> "CodeGuardian is a multi-agent code review system with 3 detection layers running in parallel.
> A Parser agent extracts ASTs, then Security and Quality agents run simultaneously using
> LangGraph's fan-out — Security runs Bandit ([FILL] issues found), Semgrep ([FILL] issues),
> and a CodeBERT model fine-tuned on CodeXGLUE Defect Detection data — with an LLM enrichment
> pass that filters false positives and adds exploitation context. A Fix Agent generates validated
> code patches using category-specific templates. A Test Writer generates pytest and jest tests.
> The Reviewer posts a structured markdown comment to GitHub. The fine-tuned CodeBERT achieved
> **[FILL] F1** on the test set vs **[FILL]** for the base model."