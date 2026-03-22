"""
Report generator for IronGuard baseline evaluation.
Generates a markdown report at ironguard_backend/results/baseline_{timestamp}.md
"""

import os
from pathlib import Path
from datetime import datetime, timezone

RESULTS_DIR = Path(__file__).parent.parent / "results"


def _pct(val: float) -> str:
    return f"{val * 100:.1f}"


def _rows_table(headers: list[str], rows: list[list]) -> str:
    """Build a markdown table."""
    header_row = "| " + " | ".join(headers) + " |"
    sep_row = "|" + "|".join(["---"] * len(headers)) + "|"
    body = "\n".join("| " + " | ".join(str(c) for c in row) + " |" for row in rows)
    return f"{header_row}\n{sep_row}\n{body}"


def _sample_block(samples: list[dict]) -> str:
    if not samples:
        return "_No samples._"
    lines = []
    for i, s in enumerate(samples, 1):
        prompt = s["prompt"].replace("\n", " ")[:100]
        lines.append(
            f"{i}. **Risk: {s.get('risk_score', '–')}** | "
            f"Classifier: `{s.get('classifier_label', '–')}` | "
            f"`{prompt}…`"
        )
    return "\n".join(lines)


def generate_report(
    run_metadata: dict,
    overall: dict,
    per_dataset: dict,
    per_category: dict,
    layer_attr: dict,
    latency: dict,
    failure: dict,
    raw_json_path: str,
) -> Path:
    """
    Generates the markdown baseline report and returns its path.
    """
    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp_str = run_metadata.get("timestamp", datetime.now(timezone.utc).isoformat())
    # Filename-safe timestamp
    fn_ts = timestamp_str[:19].replace(":", "-").replace("T", "T")
    report_path = RESULTS_DIR / f"baseline_{fn_ts}.md"

    duration = run_metadata.get("duration_seconds", 0)
    total = overall["total"]
    tp, tn, fp, fn = overall["tp"], overall["tn"], overall["fp"], overall["fn"]
    tpr = _pct(overall["true_positive_rate"])
    fpr = _pct(overall["false_positive_rate"])
    acc = _pct(overall["accuracy"])
    prec = _pct(overall["precision"])
    f1 = f"{overall['f1_score']:.3f}"

    # ── Per-dataset rows ──────────────────────────────────────────────────────
    ds_rows = []
    ds_notes = {
        "XSTest": "False positive benchmark",
        "WildJailbreak": "Adversarial evasion benchmark",
        "deepset": "Direct injection benchmark",
    }
    ds_display = {
        "XSTest": "walledai/XSTest",
        "WildJailbreak": "allenai/wildjailbreak",
        "deepset": "deepset/prompt-injections",
    }
    for ds_key, ds_name in ds_display.items():
        m = per_dataset.get(ds_key)
        if m:
            ds_rows.append([
                ds_name, m["total"],
                f"{_pct(m['accuracy'])}%",
                f"{_pct(m['true_positive_rate'])}%",
                f"{_pct(m['false_positive_rate'])}%",
                ds_notes.get(ds_key, ""),
            ])
        else:
            ds_rows.append([ds_name, 0, "N/A", "N/A", "N/A", "Dataset not loaded"])

    # ── Layer attribution rows ────────────────────────────────────────────────
    total_tp = overall["tp"] or 1  # avoid div-by-zero
    layer_rows = [
        ["Layer 1: Regex Pattern",          layer_attr["layer_1_pattern"],       f"{layer_attr['layer_1_pattern']/total_tp*100:.1f}%"],
        ["Layer 2: Semantic Similarity",     layer_attr["layer_2_semantic"],      f"{layer_attr['layer_2_semantic']/total_tp*100:.1f}%"],
        ["Layer 3: DeBERTa Classifier",      layer_attr["layer_3_classifier"],    f"{layer_attr['layer_3_classifier']/total_tp*100:.1f}%"],
        ["Layer 4: Fingerprint Engine",      layer_attr["layer_4_fingerprint"],   f"{layer_attr['layer_4_fingerprint']/total_tp*100:.1f}%"],
    ]

    # ── XSTest FP breakdown by category ──────────────────────────────────────
    xstest_results = [r for r in [] if r.get("dataset") == "XSTest"]  # placeholder
    # We derive it from per_category — filter to XSTest categories
    xstest_cats = [c for c in per_category if c.startswith("safe_")]
    xstest_fp_rows = []
    for cat in sorted(xstest_cats):
        m = per_category[cat]
        xstest_fp_rows.append([cat, m["total"], m["fp"], f"{_pct(m['false_positive_rate'])}%"])

    if not xstest_fp_rows:
        xstest_fp_table = "_No XSTest safe category data available._"
    else:
        xstest_fp_table = _rows_table(
            ["Prompt Type", "Total", "FP Count", "FP Rate"], xstest_fp_rows
        )

    # ── FN by category table ──────────────────────────────────────────────────
    fn_by_cat = failure.get("fn_by_category", {})
    fn_cat_rows = [[cat, count] for cat, count in sorted(fn_by_cat.items(), key=lambda x: -x[1])]
    fn_by_cat_table = _rows_table(["Category", "Missed Count"], fn_cat_rows) if fn_cat_rows else "_None_"

    fn_clf = failure.get("fn_classifier_breakdown", {})
    fn_clf_safe = fn_clf.get("classifier_is_safe", 0)
    fn_total = fn_clf.get("classifier_is_safe", 0) + fn_clf.get("classifier_is_malicious", 0)
    fn_safe_pct = f"{fn_clf_safe/fn_total*100:.1f}" if fn_total else "0.0"

    # ── Assemble report ────────────────────────────────────────────────────────
    report = f"""# IronGuard Security Engine — Baseline Evaluation Report
**Run Date:** {timestamp_str}  
**Total Entries Evaluated:** {total}  
**Runtime:** {duration}s  
**IronGuard Version:** {run_metadata.get('ironguard_version', 'V10')}

---

## Executive Summary

{_rows_table(
    ["Metric", "Value"],
    [
        ["Overall Accuracy", f"{acc}%"],
        ["True Positive Rate (Detection Rate)", f"{tpr}%"],
        ["False Positive Rate (Over-blocking)", f"{fpr}%"],
        ["Precision", f"{prec}%"],
        ["F1 Score", f1],
        ["Avg Pipeline Latency", f"{latency['avg_ms']}ms"],
        ["P95 Pipeline Latency", f"{latency['p95_ms']}ms"],
    ],
)}

---

## Confusion Matrix

{_rows_table(
    [" ", "Predicted: Caught", "Predicted: Passed"],
    [
        ["**Actually Attack**", f"TP: {tp}", f"FN: {fn}"],
        ["**Actually Safe**",   f"FP: {fp}", f"TN: {tn}"],
    ],
)}

---

## Per-Dataset Results

{_rows_table(
    ["Dataset", "Entries", "Accuracy", "TPR", "FPR", "Notes"],
    ds_rows,
)}

---

## Detection Layer Attribution
*(Of all correctly detected attacks, which layer caught them first)*

{_rows_table(
    ["Layer", "Catches", "% of TP"],
    layer_rows,
)}

---

## XSTest False Positive Breakdown
*(Safe prompt types that IronGuard incorrectly blocked)*

{xstest_fp_table}

---

## Failure Analysis: Missed Attacks (False Negatives)

**Total Missed:** {fn}  
**Avg Risk Score of Missed Attacks:** {failure.get('fn_avg_risk_score', 0)}  
**Missed with DeBERTa also safe:** {fn_clf_safe} ({fn_safe_pct}%)  
*(These are hardest to catch — all layers agreed they were safe)*

**Top Missed Attack Categories:**

{fn_by_cat_table}

**Sample Missed Attacks:**

{_sample_block(failure.get('fn_samples', []))}

---

## Failure Analysis: False Positives (Over-blocking)

**Total Over-blocked:** {fp}  
**Sample Over-blocked Prompts:**

{_sample_block(failure.get('fp_samples', []))}

---

## Latency Profile

{_rows_table(
    ["Stat", "Value"],
    [
        ["Min",    f"{latency['min_ms']}ms"],
        ["Avg",    f"{latency['avg_ms']}ms"],
        ["Median", f"{latency['median_ms']}ms"],
        ["P95",    f"{latency['p95_ms']}ms"],
        ["Max",    f"{latency['max_ms']}ms"],
    ],
)}

---

## Interpretation Notes

- **TPR < 80%** → Detection gaps exist. V3 mutation engine needed to identify specific evasion patterns.
- **FPR > 10%** → Over-blocking is significant. Safe prompts being blocked by regex patterns that are too broad.
- **High Layer 1 attribution** → System relies heavily on regex. Adversarial attacks that rephrase will bypass.
- **High FN + DeBERTa safe** → Attacks that bypass all layers. These are prime candidates for fingerprint learning.

---

## Raw Results

Saved to: `{raw_json_path}`
"""

    report_path.write_text(report, encoding="utf-8")
    return report_path
