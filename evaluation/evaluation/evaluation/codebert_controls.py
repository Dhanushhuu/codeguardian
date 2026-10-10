#!/usr/bin/env python3
"""
Control experiments for the CodeBERT transfer result.

Observed: on the hand-written Python benchmark the fine-tuned model gave P(vulnerable) ~= 0.998 for
EVERY snippet (safe and vulnerable alike). Two competing explanations:
  (A) Evaluation bug (wrong model, wrong preprocessing)  -> Control 1 would also look broken.
  (B) Real domain shift (C-trained model sees Python as "out of distribution") -> Control 1 is
      normal (~61% accuracy, ~45% flagged) while Control 2 flags (almost) everything.
Control 2 additionally checks whether the effect is about Python in general or just very short snippets.

Colab:  !python codebert_controls.py --model-dir "/content/drive/MyDrive/codeguardian/codebert-vulnerability-detector"
Needs:  pip install -q transformers torch datasets scikit-learn
"""
import argparse
import inspect
import random
import textwrap

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


def load(model_dir):
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    tok = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir).to(dev).eval()
    return tok, model, dev


def probs(tok, model, dev, codes, bs=8):
    out = []
    for i in range(0, len(codes), bs):
        enc = tok(codes[i:i + bs], truncation=True, max_length=512, padding=True,
                  return_tensors="pt").to(dev)
        with torch.no_grad():
            out += torch.softmax(model(**enc).logits, dim=-1)[:, 1].tolist()
    return out


def control1_devign(tok, model, dev, n, seed):
    from datasets import load_dataset
    ds = load_dataset("google/code_x_glue_cc_defect_detection", split="test")
    idx = random.Random(seed).sample(range(len(ds)), n)
    codes = [ds[i]["func"] for i in idx]
    labels = [int(ds[i]["target"]) for i in idx]
    p = probs(tok, model, dev, codes)
    preds = [int(x >= 0.5) for x in p]
    acc = sum(int(a == b) for a, b in zip(preds, labels)) / n
    print(f"\nControl 1 - Devign test sample (C), n={n}")
    print(f"  accuracy {acc:.3f} (full-test accuracy was 0.615)")
    print(f"  flagged as vulnerable {sum(preds)/n:.2%} (about 45% expected)")
    print(f"  mean P(vuln): vulnerable {mean([x for x, y in zip(p, labels) if y == 1]):.3f} | "
          f"safe {mean([x for x, y in zip(p, labels) if y == 0]):.3f}")
    print(f"  median code length: {sorted(len(c) for c in codes)[n//2]} chars")


def mean(xs):
    return sum(xs) / len(xs) if xs else float("nan")


def stdlib_functions(limit):
    import argparse as _a, base64, calendar, csv, difflib, fnmatch, glob, ipaddress, json, posixpath, shlex, shutil, textwrap as _t, tokenize, urllib.parse, zipfile  # noqa
    mods = [_a, base64, calendar, csv, difflib, fnmatch, glob, ipaddress, json, posixpath, shlex, shutil, _t, tokenize, urllib.parse, zipfile]
    seen, funcs = set(), []
    for m in mods:
        members = list(inspect.getmembers(m, inspect.isfunction))
        for _, f in members:
            if f.__module__ != m.__name__:
                continue
            try:
                src = textwrap.dedent(inspect.getsource(f))
            except (OSError, TypeError):
                continue
            if 300 < len(src) < 3000 and src not in seen:
                seen.add(src)
                funcs.append(src)
    random.Random(0).shuffle(funcs)
    return funcs[:limit]


def control2_python(tok, model, dev, limit):
    codes = stdlib_functions(limit)
    p = probs(tok, model, dev, codes)
    flagged = sum(int(x >= 0.5) for x in p) / len(p)
    print(f"\nControl 2 - real Python stdlib functions (long, benign, not security-related), n={len(codes)}")
    print(f"  flagged as vulnerable {flagged:.2%}")
    print(f"  mean P(vuln) {mean(p):.3f} | min {min(p):.3f} | max {max(p):.3f}")
    print(f"  median code length: {sorted(len(c) for c in codes)[len(codes)//2]} chars")
    if flagged >= 0.9:
        print("  -> Flags nearly all Python even for long benign functions: a language-level shift, "
              "not just a snippet-length effect.")
    elif flagged <= 0.6:
        print("  -> Not saturated on long Python functions: the earlier result may be driven by very short snippets.")
    else:
        print("  -> Mixed: partially saturated; report both results.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", required=True)
    ap.add_argument("--n-devign", type=int, default=300)
    ap.add_argument("--n-python", type=int, default=150)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    tok, model, dev = load(a.model_dir)
    control1_devign(tok, model, dev, a.n_devign, a.seed)
    control2_python(tok, model, dev, a.n_python)
