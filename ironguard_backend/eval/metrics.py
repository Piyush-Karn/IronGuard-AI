"""
Metrics computation for IronGuard baseline evaluation.
All functions take results: list[dict] and return structured dicts.
"""

import statistics
from collections import defaultdict


def _safe_div(num: float, denom: float) -> float:
    return num / denom if denom else 0.0


def _bucket(results: list[dict]) -> tuple[int, int, int, int, int]:
    """Returns (tp, tn, fp, fn, errors) counts."""
    tp = sum(1 for r in results if r.get("outcome_type") == "TP")
    tn = sum(1 for r in results if r.get("outcome_type") == "TN")
    fp = sum(1 for r in results if r.get("outcome_type") == "FP")
    fn = sum(1 for r in results if r.get("outcome_type") == "FN")
    errors = sum(1 for r in results if r.get("outcome_type") == "ERROR")
    return tp, tn, fp, fn, errors


def _build_metrics(results: list[dict]) -> dict:
    tp, tn, fp, fn, errors = _bucket(results)
    total = len(results)
    correct = tp + tn
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return {
        "total": total,
        "correct": correct,
        "accuracy": round(_safe_div(correct, total), 4),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "errors": errors,
        "true_positive_rate": round(_safe_div(tp, tp + fn), 4),
        "false_positive_rate": round(_safe_div(fp, fp + tn), 4),
        "precision": round(precision, 4),
        "f1_score": round(f1, 4),
    }


def compute_overall_metrics(results: list[dict]) -> dict:
    return _build_metrics(results)


def compute_per_dataset_metrics(results: list[dict]) -> dict:
    by_ds: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        by_ds[r.get("dataset", "unknown")].append(r)
    return {ds: _build_metrics(entries) for ds, entries in by_ds.items()}


def compute_per_category_metrics(results: list[dict]) -> dict:
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        by_cat[r.get("category", "unknown")].append(r)
    return {cat: _build_metrics(entries) for cat, entries in by_cat.items()}


def compute_layer_attribution(results: list[dict]) -> dict:
    """
    For TP entries (attacks correctly caught), determine which layer caught them.
    Priority: Layer 4 → Layer 3 → Layer 1 → Layer 2
    """
    counters = {
        "layer_1_pattern": 0,
        "layer_2_semantic": 0,
        "layer_3_classifier": 0,
        "layer_4_fingerprint": 0,
        "unknown": 0,
    }
    for r in results:
        if r.get("outcome_type") != "TP":
            continue
        if r.get("fingerprint_match"):
            counters["layer_4_fingerprint"] += 1
        elif r.get("classifier_is_malicious"):
            counters["layer_3_classifier"] += 1
        elif r.get("base_risk_score", 0) >= 30 and r.get("attack_types"):
            counters["layer_1_pattern"] += 1
        else:
            counters["layer_2_semantic"] += 1
    return counters


def compute_latency_stats(results: list[dict]) -> dict:
    lats = [r["latency_ms"] for r in results if r.get("latency_ms") is not None]
    if not lats:
        return {"avg_ms": 0, "median_ms": 0, "p95_ms": 0, "max_ms": 0, "min_ms": 0}
    lats_sorted = sorted(lats)
    p95_idx = int(len(lats_sorted) * 0.95)
    return {
        "avg_ms": round(sum(lats) / len(lats), 2),
        "median_ms": round(statistics.median(lats), 2),
        "p95_ms": round(lats_sorted[min(p95_idx, len(lats_sorted) - 1)], 2),
        "max_ms": round(max(lats), 2),
        "min_ms": round(min(lats), 2),
    }


def compute_failure_analysis(results: list[dict]) -> dict:
    fns = [r for r in results if r.get("outcome_type") == "FN"]
    fps = [r for r in results if r.get("outcome_type") == "FP"]

    fn_by_cat: dict[str, int] = defaultdict(int)
    for r in fns:
        fn_by_cat[r.get("category", "unknown")] += 1

    fp_by_cat: dict[str, int] = defaultdict(int)
    for r in fps:
        fp_by_cat[r.get("category", "unknown")] += 1

    fn_avg_risk = _safe_div(
        sum(r.get("risk_score", 0) for r in fns), len(fns)
    ) if fns else 0.0

    fn_clf_safe = sum(
        1 for r in fns if not r.get("classifier_is_malicious", False)
    )
    fn_clf_malicious = len(fns) - fn_clf_safe

    fn_samples = [
        {
            "prompt": r["prompt"][:120],
            "risk_score": r.get("risk_score", 0),
            "classifier_label": r.get("classifier_label", ""),
        }
        for r in fns[:5]
    ]
    fp_samples = [
        {
            "prompt": r["prompt"][:120],
            "risk_score": r.get("risk_score", 0),
            "classifier_label": r.get("classifier_label", ""),
        }
        for r in fps[:5]
    ]

    return {
        "fn_by_category": dict(fn_by_cat),
        "fp_by_category": dict(fp_by_cat),
        "fn_samples": fn_samples,
        "fp_samples": fp_samples,
        "fn_avg_risk_score": round(fn_avg_risk, 2),
        "fn_classifier_breakdown": {
            "classifier_is_safe": fn_clf_safe,
            "classifier_is_malicious": fn_clf_malicious,
        },
    }
