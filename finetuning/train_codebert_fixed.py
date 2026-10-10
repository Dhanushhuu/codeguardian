# CodeBERT fine-tuning on CodeXGLUE Defect Detection (Devign) -- Colab cell
# Fixes vs. the original run:
#   1. Model selection uses the VALIDATION split; the TEST split is used once, at the end.
#   2. Checkpoints and results are written to Google Drive so a disconnect/interrupt loses nothing.
#   3. Training resumes from the last checkpoint if one exists.
#   4. Dynamic padding (faster than padding every sample to 512).
#   5. Reports the majority-class baseline and a confusion matrix, so the numbers can be interpreted.

!pip install -q transformers datasets scikit-learn torch accelerate

import json, os
from pathlib import Path
import numpy as np
import torch
from datasets import load_dataset
from google.colab import drive
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          DataCollatorWithPadding, EvalPrediction, Trainer,
                          TrainingArguments, set_seed)
from transformers.trainer_utils import get_last_checkpoint

drive.mount("/content/drive")

MODEL_NAME = "microsoft/codebert-base"
OUTPUT_DIR = "/content/drive/MyDrive/codeguardian/codebert-vulnerability-detector"
EPOCHS, BATCH_SIZE, MAX_LENGTH, LR, SEED = 3, 8, 512, 2e-5, 42

set_seed(SEED)
Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
device = "cuda" if torch.cuda.is_available() else "cpu"
print("Device:", device)

# ---------------- data ----------------
dataset = load_dataset("google/code_x_glue_cc_defect_detection")  # namespaced id required by newer huggingface_hub
train_raw, valid_raw, test_raw = dataset["train"], dataset["validation"], dataset["test"]
print(f"Train {len(train_raw)} | Validation {len(valid_raw)} | Test {len(test_raw)}")

# Class balance -> majority-class baseline accuracy (what a model that always says "safe" would score)
test_labels = np.array([int(t) for t in test_raw["target"]])
vuln_ratio = test_labels.mean()
print(f"Test vulnerable ratio: {vuln_ratio:.3f} | majority baseline accuracy: {max(vuln_ratio, 1 - vuln_ratio):.3f}")

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

def tokenize(batch):
    tokens = tokenizer(batch["func"], truncation=True, max_length=MAX_LENGTH)
    tokens["labels"] = [int(t) for t in batch["target"]]
    return tokens

train_ds = train_raw.map(tokenize, batched=True, remove_columns=train_raw.column_names)
valid_ds = valid_raw.map(tokenize, batched=True, remove_columns=valid_raw.column_names)
test_ds = test_raw.map(tokenize, batched=True, remove_columns=test_raw.column_names)

model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)
# The "classifier.* MISSING" load report is expected: the classification head is new and gets trained.

def compute_metrics(p: EvalPrediction):
    preds = np.argmax(p.predictions, axis=1)
    return {
        "accuracy": float(accuracy_score(p.label_ids, preds)),
        "f1": float(f1_score(p.label_ids, preds, average="binary")),
        "precision": float(precision_score(p.label_ids, preds, average="binary", zero_division=0)),
        "recall": float(recall_score(p.label_ids, preds, average="binary", zero_division=0)),
    }

args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    num_train_epochs=EPOCHS,
    per_device_train_batch_size=BATCH_SIZE,
    per_device_eval_batch_size=BATCH_SIZE * 2,
    learning_rate=LR, warmup_steps=200, weight_decay=0.01,
    eval_strategy="epoch", save_strategy="epoch", save_total_limit=2,
    load_best_model_at_end=True, metric_for_best_model="f1",
    logging_steps=50, report_to="none", seed=SEED,
    fp16=torch.cuda.is_available(),
)

trainer = Trainer(
    model=model, args=args,
    train_dataset=train_ds,
    eval_dataset=valid_ds,                       # validation split, NOT test
    data_collator=DataCollatorWithPadding(tokenizer),
    compute_metrics=compute_metrics,
)

last_ckpt = get_last_checkpoint(OUTPUT_DIR) if os.path.isdir(OUTPUT_DIR) else None
print("Resuming from:", last_ckpt)
trainer.train(resume_from_checkpoint=last_ckpt)

trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)

# ---------------- final evaluation ----------------
val_metrics = trainer.evaluate()                 # best model on validation
pred_out = trainer.predict(test_ds)              # test set touched exactly once
test_metrics = {k.replace("test_", ""): v for k, v in pred_out.metrics.items()
                if k.startswith("test_") and k in ("test_accuracy", "test_f1", "test_precision", "test_recall")}
test_preds = np.argmax(pred_out.predictions, axis=1)
cm = confusion_matrix(pred_out.label_ids, test_preds)  # [[TN, FP], [FN, TP]]

results = {
    "validation": {k: v for k, v in val_metrics.items() if k.startswith("eval_")},
    "test": test_metrics,
    "test_confusion_matrix": {"TN": int(cm[0][0]), "FP": int(cm[0][1]),
                              "FN": int(cm[1][0]), "TP": int(cm[1][1])},
    "test_vulnerable_ratio": float(vuln_ratio),
    "majority_baseline_accuracy": float(max(vuln_ratio, 1 - vuln_ratio)),
    "config": {"model": MODEL_NAME, "epochs": EPOCHS, "batch_size": BATCH_SIZE,
               "lr": LR, "max_length": MAX_LENGTH, "seed": SEED},
}
with open(f"{OUTPUT_DIR}/eval_results.json", "w") as f:
    json.dump(results, f, indent=2)

print(json.dumps(results, indent=2))
