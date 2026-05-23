"""
PhishGuard - ML Model Trainer  (improved)
==========================================
• Chunked CSV loading  → fixes MemoryError on large datasets
• Per-dataset row cap  → keeps RAM under control
• Class balancing      → handles imbalanced spam/ham ratios
• Two-model comparison → Logistic Regression vs SGD (fast SVM-like)
• Best model saved     → picks whichever scores higher F1
• Calibrated probas    → reliable confidence scores for the Flask app
• Full metrics report  → accuracy, F1, ROC-AUC, confusion matrix
• model/label_map.json → human-readable label info saved alongside pkl

Outputs
-------
  model/model.pkl        – trained classifier (CalibratedClassifierCV)
  model/vectorizer.pkl   – fitted TfidfVectorizer
  model/label_map.json   – {0: "safe", 1: "phishing"}
  model/training_report.txt – full evaluation saved to disk
"""

import gc
import json
import os
import re
import sys
import time
import warnings
from datetime import datetime

import joblib
import nltk
import numpy as np
import pandas as pd

from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.utils import resample

warnings.filterwarnings("ignore")

# ── NLTK setup ─────────────────────────────────────────────────────────
nltk.download("stopwords", quiet=True)
nltk.download("punkt",     quiet=True)
from nltk.corpus import stopwords

STOP_WORDS = set(stopwords.words("english"))

# ══════════════════════════════════════════════════════════════════════
#  CONFIG  –  tweak these if you hit memory issues
# ══════════════════════════════════════════════════════════════════════
MODEL_DIR       = "model"
CHUNK_SIZE      = 10_000   # rows read at a time per CSV
MAX_ROWS_PER_DS = 60_000   # hard cap per dataset  (set None = no cap)
MAX_FEATURES    = 40_000   # TF-IDF vocabulary size
NGRAM_RANGE     = (1, 2)
TEST_SIZE       = 0.20
RANDOM_STATE    = 42

# Dataset configs: (filename, [text_columns], label_column)
DATASETS = [
    ("CEAS_08.csv",        ["subject", "body"], "label"),
    ("Enron.csv",          ["subject", "body"], "label"),
    ("Ling.csv",           ["subject", "body"], "label"),
    ("Nazario.csv",        ["subject", "body"], "label"),
    ("Nigerian_Fraud.csv", ["subject", "body"], "label"),
    ("phishing_email.csv", ["text_combined"],   "label"),
]

os.makedirs(MODEL_DIR, exist_ok=True)
# ══════════════════════════════════════════════════════════════════════


# ── Helpers ────────────────────────────────────────────────────────────
def log(msg: str, indent: int = 2) -> None:
    print(" " * indent + msg, flush=True)


def separator(char: str = "─", width: int = 52, indent: int = 2) -> None:
    print(" " * indent + char * width, flush=True)


# ── Text preprocessing ─────────────────────────────────────────────────
_URL_RE   = re.compile(r"http\S+|www\S+")
_EMAIL_RE = re.compile(r"\S+@\S+")
_NONALPHA = re.compile(r"[^a-z\s]")
_SPACES   = re.compile(r"\s+")

def preprocess(text: str) -> str:
    if not isinstance(text, str) or not text.strip():
        return ""
    text = text.lower()
    text = _URL_RE.sub(" urltoken ", text)
    text = _EMAIL_RE.sub(" emailtoken ", text)
    text = _NONALPHA.sub(" ", text)
    tokens = _SPACES.sub(" ", text).strip().split()
    tokens = [t for t in tokens if t not in STOP_WORDS and len(t) > 2]
    return " ".join(tokens)


PREPROCESS_BATCH = 5_000   # rows processed at a time – keeps RAM flat

def _clean_batch(texts: list[str]) -> list[str]:
    """Apply all regex + stopword removal to a plain Python list."""
    out = []
    for text in texts:
        if not isinstance(text, str) or not text.strip():
            out.append("")
            continue
        text = text.lower()
        text = _URL_RE.sub(" urltoken ", text)
        text = _EMAIL_RE.sub(" emailtoken ", text)
        text = _NONALPHA.sub(" ", text)
        tokens = _SPACES.sub(" ", text).strip().split()
        tokens = [t for t in tokens if t not in STOP_WORDS and len(t) > 2]
        out.append(" ".join(tokens))
    return out


def preprocess_series(series: pd.Series) -> pd.Series:
    """Memory-safe batched preprocessing – processes PREPROCESS_BATCH rows at a time."""
    arr    = series.fillna("").astype(str).to_numpy()
    result = []
    total  = len(arr)
    for start in range(0, total, PREPROCESS_BATCH):
        batch = arr[start: start + PREPROCESS_BATCH].tolist()
        result.extend(_clean_batch(batch))
        if (start // PREPROCESS_BATCH) % 10 == 0:
            pct = min(start + PREPROCESS_BATCH, total) / total * 100
            print(f"\r    preprocessing … {pct:5.1f}%", end="", flush=True)
    print(f"\r    preprocessing … 100.0%  ({total:,} rows)          ")
    return pd.Series(result, index=series.index, dtype="object")


# ── Chunked CSV loader ─────────────────────────────────────────────────
def load_dataset(filename: str, text_cols: list, label_col: str) -> pd.DataFrame | None:
    if not os.path.exists(filename):
        log(f"[SKIP] {filename} – file not found")
        return None

    chunks_out = []

    for encoding in ("utf-8", "latin-1"):
        try:
            reader = pd.read_csv(
                filename,
                encoding=encoding,
                on_bad_lines="skip",
                chunksize=CHUNK_SIZE,
                low_memory=True,
            )
            for chunk in reader:
                # ── column check (once, on first chunk) ──
                if not chunks_out:
                    missing = [c for c in text_cols + [label_col] if c not in chunk.columns]
                    if missing:
                        log(f"[SKIP] {filename} – missing columns: {missing}")
                        return None

                # ── build text + label ──
                chunk["text"] = (
                    chunk[text_cols]
                    .fillna("")
                    .apply(lambda r: " ".join(r.values.astype(str)), axis=1)
                )
                chunk["label"] = pd.to_numeric(chunk[label_col], errors="coerce")
                chunk = chunk.dropna(subset=["label", "text"])
                chunk["label"] = chunk["label"].astype(int)
                chunk = chunk[chunk["label"].isin([0, 1])]

                if len(chunk):
                    chunks_out.append(chunk[["text", "label"]].copy())

                # honour per-dataset row cap early
                if MAX_ROWS_PER_DS and sum(len(c) for c in chunks_out) >= MAX_ROWS_PER_DS:
                    break

            break  # encoding worked

        except UnicodeDecodeError:
            continue
        except Exception as exc:
            log(f"[ERROR] {filename} – {exc}")
            return None

    if not chunks_out:
        log(f"[WARN]  {filename} – no usable rows after filtering")
        return None

    df = pd.concat(chunks_out, ignore_index=True)

    # Apply row cap after concat (in case last chunk pushed us over)
    if MAX_ROWS_PER_DS and len(df) > MAX_ROWS_PER_DS:
        # Stratified sample to preserve class ratio
        df = (
            df.groupby("label", group_keys=False)
            .apply(lambda x: x.sample(
                min(len(x), int(MAX_ROWS_PER_DS * len(x) / len(df))),
                random_state=RANDOM_STATE,
            ))
            .reset_index(drop=True)
        )

    n_phish = (df["label"] == 1).sum()
    n_safe  = (df["label"] == 0).sum()
    log(f"[OK]    {filename} → {len(df):,} rows  |  phishing: {n_phish:,}  |  safe: {n_safe:,}")
    return df


# ── Balance dataset ────────────────────────────────────────────────────
def balance_classes(df: pd.DataFrame) -> pd.DataFrame:
    """Upsample minority class so ratio ≤ 2:1."""
    counts = df["label"].value_counts()
    majority_label = counts.idxmax()
    minority_label = counts.idxmin()
    n_maj = counts[majority_label]
    n_min = counts[minority_label]

    if n_maj / max(n_min, 1) <= 2.0:
        return df  # already balanced enough

    minority_df  = df[df["label"] == minority_label]
    majority_df  = df[df["label"] == majority_label]
    upsampled    = resample(minority_df, replace=True,
                            n_samples=min(n_maj, n_min * 2),
                            random_state=RANDOM_STATE)
    balanced = pd.concat([majority_df, upsampled], ignore_index=True)
    log(f"  class balance: {n_maj:,} majority → upsample minority {n_min:,} → {len(upsampled):,}")
    return balanced.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)


# ── Build & evaluate a model ───────────────────────────────────────────
def build_model(name: str, clf, X_train_tfidf, y_train,
                X_test_tfidf, y_test) -> tuple[object, float, str]:
    """Train clf, calibrate, return (calibrated_clf, f1_macro, report_str)."""
    log(f"Training {name}...")

    # Wrap with Platt scaling for reliable predict_proba
    calibrated = CalibratedClassifierCV(clf, cv=3, method="sigmoid")
    calibrated.fit(X_train_tfidf, y_train)

    y_pred  = calibrated.predict(X_test_tfidf)
    y_proba = calibrated.predict_proba(X_test_tfidf)[:, 1]

    acc     = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)
    report  = classification_report(y_test, y_pred, target_names=["Safe", "Phishing"])
    cm      = confusion_matrix(y_test, y_pred)

    # F1 macro as selection criterion
    from sklearn.metrics import f1_score
    f1 = f1_score(y_test, y_pred, average="macro")

    lines = [
        f"  Model       : {name}",
        f"  Accuracy    : {acc*100:.2f}%",
        f"  ROC-AUC     : {roc_auc:.4f}",
        f"  F1 (macro)  : {f1:.4f}",
        "",
        report,
        "  Confusion matrix:",
        "                Predicted",
        "                Safe    Phishing",
        f"  Actual Safe   {cm[0][0]:6d}  {cm[0][1]:6d}",
        f"  Actual Phish  {cm[1][0]:6d}  {cm[1][1]:6d}",
    ]
    report_str = "\n".join(lines)
    print("\n" + report_str + "\n")
    return calibrated, f1, report_str


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════
def main() -> None:
    t_start = time.time()
    print()
    separator("═")
    log("PhishGuard ML Trainer  –  " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"), indent=2)
    separator("═")

    # ── 1. Load datasets ───────────────────────────────────────────────
    log("\nLoading datasets...")
    separator()
    all_dfs = []
    for filename, text_cols, label_col in DATASETS:
        df = load_dataset(filename, text_cols, label_col)
        if df is not None:
            all_dfs.append(df)

    if not all_dfs:
        log("\n[ERROR] No datasets loaded. Place CSV files in the same folder as this script.")
        sys.exit(1)

    # ── 2. Combine & deduplicate ───────────────────────────────────────
    separator()
    log("\nCombining datasets...")
    combined = pd.concat(all_dfs, ignore_index=True)
    del all_dfs; gc.collect()

    before = len(combined)
    combined.drop_duplicates(subset="text", inplace=True)
    after  = len(combined)
    log(f"Deduplicated: {before:,} → {after:,} rows  ({before-after:,} removed)")

    log(f"\nCombined dataset:")
    log(f"  Total rows   : {len(combined):,}")
    log(f"  Phishing (1) : {(combined['label']==1).sum():,}")
    log(f"  Safe (0)     : {(combined['label']==0).sum():,}")

    # ── 3. Balance ─────────────────────────────────────────────────────
    separator()
    log("\nBalancing classes...")
    combined = balance_classes(combined)

    # ── 4. Preprocess ──────────────────────────────────────────────────
    separator()
    log("\nPreprocessing text (vectorised)...")
    combined["text_clean"] = preprocess_series(combined["text"])
    del combined["text"]; gc.collect()

    combined = combined[combined["text_clean"].str.len() > 5].reset_index(drop=True)
    log(f"Rows after cleaning: {len(combined):,}")

    # ── 5. Train / test split ──────────────────────────────────────────
    X = combined["text_clean"]
    y = combined["label"]
    del combined; gc.collect()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    log(f"\nSplit  →  train: {len(X_train):,}  |  test: {len(X_test):,}")

    # ── 6. TF-IDF ─────────────────────────────────────────────────────
    separator()
    log("\nFitting TF-IDF vectorizer...")
    vectorizer = TfidfVectorizer(
        max_features=MAX_FEATURES,
        ngram_range=NGRAM_RANGE,
        min_df=2,
        sublinear_tf=True,
        strip_accents="unicode",
        analyzer="word",
    )
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf  = vectorizer.transform(X_test)
    log(f"Vocabulary size: {len(vectorizer.vocabulary_):,}")

    # ── 7. Train candidate models ──────────────────────────────────────
    separator()
    log("\nTraining candidate models...")
    separator()

    lr = LogisticRegression(
        C=1.0,
        max_iter=1000,
        class_weight="balanced",
        solver="saga",        # faster than lbfgs on large sparse data
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )

    sgd = SGDClassifier(
        loss="modified_huber",  # supports predict_proba natively
        alpha=1e-4,
        max_iter=200,
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_STATE,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=5,
    )

    results = {}
    for name, clf in [("Logistic Regression", lr), ("SGD Classifier", sgd)]:
        cal_clf, f1, report = build_model(
            name, clf, X_train_tfidf, y_train, X_test_tfidf, y_test
        )
        results[name] = {"clf": cal_clf, "f1": f1, "report": report}

    # ── 8. Pick best model ─────────────────────────────────────────────
    separator()
    best_name = max(results, key=lambda k: results[k]["f1"])
    best_clf  = results[best_name]["clf"]
    best_f1   = results[best_name]["f1"]
    log(f"\n✓ Best model: {best_name}  (F1 macro = {best_f1:.4f})")

    # ── 9. Save artefacts ──────────────────────────────────────────────
    separator()
    model_path      = os.path.join(MODEL_DIR, "model.pkl")
    vectorizer_path = os.path.join(MODEL_DIR, "vectorizer.pkl")
    label_map_path  = os.path.join(MODEL_DIR, "label_map.json")
    report_path     = os.path.join(MODEL_DIR, "training_report.txt")

    joblib.dump(best_clf,   model_path,      compress=3)
    joblib.dump(vectorizer, vectorizer_path, compress=3)

    with open(label_map_path, "w") as f:
        json.dump({"0": "safe", "1": "phishing",
                   "best_model": best_name,
                   "f1_macro": round(best_f1, 4),
                   "trained_at": datetime.now().isoformat()}, f, indent=2)

    full_report = "\n\n".join(
        [f"=== {n} ===\n{d['report']}" for n, d in results.items()]
    )
    with open(report_path, "w") as f:
        f.write(full_report)

    elapsed = time.time() - t_start
    separator("═")
    log(f"\n  Saved → {model_path}")
    log(f"  Saved → {vectorizer_path}")
    log(f"  Saved → {label_map_path}")
    log(f"  Saved → {report_path}")
    log(f"\n  Total time : {elapsed:.1f}s")
    log(f"  Best model : {best_name}")
    log(f"  F1 macro   : {best_f1:.4f}")
    log(f"\n  Training complete!  Run:  python App.py")
    separator("═")
    print()


if __name__ == "__main__":
    main()