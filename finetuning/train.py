# """
# finetuning/train.py
# Fine-tunes CodeBERT for binary vulnerability classification on the
# CodeXGLUE Defect Detection dataset (based on Devign).

# Run on Google Colab T4 GPU (free tier):
#   !pip install transformers datasets scikit-learn torch
#   !python finetuning/train.py

# After training completes:
#   1. Download the folder: data/models/codebert-vulnerability-detector/
#   2. Place it in your project at that same path
#   3. Set USE_FINETUNED_MODEL=true in your .env file
#   4. Fill real numbers from eval_results.json into EVALUATION.md
# """

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)

# ─── Config ───────────────────────────────────────────────────────────────────

MODEL_NAME    = "microsoft/codebert-base"
DATASET_NAME  = "code_x_glue_cc_defect_detection"
OUTPUT_DIR    = "data/models/codebert-vulnerability-detector"
EPOCHS        = 3
BATCH_SIZE    = 8
LEARNING_RATE = 2e-5
MAX_LENGTH    = 512


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    # ── Imports ───────────────────────────────────────────────────────────────
    try:
        import numpy as np
        import torch
        from datasets import load_dataset
        from sklearn.metrics import (
            accuracy_score,
            f1_score,
            precision_score,
            recall_score,
        )
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            EvalPrediction,
            Trainer,
            TrainingArguments,
        )
    except ImportError as exc:
        logger.error(
            "Missing dependency: %s\n"
            "Run: pip install transformers datasets scikit-learn torch",
            exc,
        )
        raise

    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info("Device: %s", device)

    # ── Load dataset ──────────────────────────────────────────────────────────
    logger.info("Loading dataset: %s", DATASET_NAME)
    dataset  = load_dataset(DATASET_NAME)
    train_ds = dataset["train"]
    test_ds  = dataset["test"]
    logger.info("Train: %d samples | Test: %d samples", len(train_ds), len(test_ds))

    # ── Tokenise ──────────────────────────────────────────────────────────────
    logger.info("Loading tokenizer: %s", MODEL_NAME)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    def tokenize(batch: dict) -> dict:
        return tokenizer(
            batch["func"],
            truncation=True,
            padding="max_length",
            max_length=MAX_LENGTH,
        )

    logger.info("Tokenising — this takes a few minutes…")
    remove_cols = ["func", "project", "commit_id"]

    train_ds = train_ds.map(tokenize, batched=True, remove_columns=remove_cols)
    test_ds  = test_ds.map(tokenize,  batched=True, remove_columns=remove_cols)

    train_ds = train_ds.rename_column("target", "labels")
    test_ds  = test_ds.rename_column("target", "labels")

    train_ds.set_format("torch")
    test_ds.set_format("torch")

    # ── Model ─────────────────────────────────────────────────────────────────
    logger.info("Loading model: %s", MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=2,
        ignore_mismatched_sizes=True,
    )
    model.to(device)

    # ── Metrics ───────────────────────────────────────────────────────────────
    def compute_metrics(p: EvalPrediction) -> dict:
        preds  = np.argmax(p.predictions, axis=1)
        labels = p.label_ids
        return {
            "accuracy":  float(accuracy_score(labels, preds)),
            "f1":        float(f1_score(labels, preds, average="binary")),
            "precision": float(precision_score(labels, preds, average="binary", zero_division=0)),
            "recall":    float(recall_score(labels, preds, average="binary", zero_division=0)),
        }

    # ── Training arguments ────────────────────────────────────────────────────
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

    training_args = TrainingArguments(
        output_dir                  = OUTPUT_DIR,
        num_train_epochs            = EPOCHS,
        per_device_train_batch_size = BATCH_SIZE,
        per_device_eval_batch_size  = BATCH_SIZE,
        learning_rate               = LEARNING_RATE,
        warmup_ratio                = 0.1,
        weight_decay                = 0.01,
        evaluation_strategy         = "epoch",
        save_strategy               = "epoch",
        load_best_model_at_end      = True,
        metric_for_best_model       = "f1",
        logging_dir                 = f"{OUTPUT_DIR}/logs",
        logging_steps               = 50,
        report_to                   = "none",
        fp16                        = torch.cuda.is_available(),
    )

    # ── Train ─────────────────────────────────────────────────────────────────
    trainer = Trainer(
        model           = model,
        args            = training_args,
        train_dataset   = train_ds,
        eval_dataset    = test_ds,
        compute_metrics = compute_metrics,
    )

    logger.info("Starting training — %d epochs, batch size %d…", EPOCHS, BATCH_SIZE)
    trainer.train()

    # ── Save ──────────────────────────────────────────────────────────────────
    logger.info("Saving model to %s", OUTPUT_DIR)
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)

    # ── Evaluate and save results ─────────────────────────────────────────────
    logger.info("Running final evaluation…")
    metrics = trainer.evaluate()

    results_path = Path(OUTPUT_DIR) / "eval_results.json"
    with open(results_path, "w") as f:
        json.dump(metrics, f, indent=2)

    logger.info("Eval results saved to %s", results_path)

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print("  TRAINING COMPLETE")
    print("=" * 60)
    print(f"  F1 Score  : {metrics.get('eval_f1', 0):.4f}")
    print(f"  Accuracy  : {metrics.get('eval_accuracy', 0):.4f}")
    print(f"  Precision : {metrics.get('eval_precision', 0):.4f}")
    print(f"  Recall    : {metrics.get('eval_recall', 0):.4f}")
    print()
    print(f"  Model saved → {OUTPUT_DIR}/")
    print(f"  Results   → {results_path}")
    print()
    print("  Next steps:")
    print("  1. Copy data/models/ folder back into your project")
    print("  2. Set USE_FINETUNED_MODEL=true in your .env")
    print("  3. Fill EVALUATION.md with the numbers above")
    print("=" * 60)


if __name__ == "__main__":
    main()