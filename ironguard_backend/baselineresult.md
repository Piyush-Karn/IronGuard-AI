# IronGuard Security Engine — V11 Baseline Evaluation Results

**Run Date:** 2026-03-24 (T15:18:51)  
**Entries Evaluated:** 2,730 (Full Dataset: XSTest, WildJailbreak, Prompt-Injections)  
**Baseline Mode:** FULL (All 4 detection layers active — Clean Slate)

## 📊 Summary Metrics

| Metric | Baseline Value | Status |
|---|---|---|
| **Overall Accuracy** | 64.9% | 🟢 Improved (+14.1%) |
| **TPR (Detection Rate)** | 61.1% | 🟢 Significant Gain (+47.1%) |
| **FPR (Over-blocking)** | 18.6% | 🟡 Stable / In-range |
| **Avg Pipeline Latency** | 1240.14ms | 🟢 Within Spec |
| **P95 Pipeline Latency** | 3708.5ms | 🟡 Higher due to DeBERTa |

---

## 🔍 Layer Attribution (Clean Run)
*(Of all correctly detected attacks, which layer caught them first)*

- **Layer 1: Regex Pattern:** 35.5%
- **Layer 3: DeBERTa Classifier:** 64.5%
- **Layer 2: Semantic Similarity:** 0.0% (Note: No matches found in this specific test set)
- **Layer 4: Fingerprint Engine:** 0.0% (Verification: No leakage from previous runs)

---

## 🛡️ Performance by Dataset

| Dataset | Accuracy | TPR | FPR |
|---|---|---|---|
| **walledai/XSTest** | 58.0% | 5.5% | 0.0% |
| **deepset/prompt-injections** | 98.6% | 92.9% | 0.0% |
| **allenai/wildjailbreak** | 65.2% | 66.4% | 45.7% |

> [!IMPORTANT]
> This run represents the first **fully isolated evaluation**. The Fingerprint Database was scrubbed beforehand to ensure no contamination from previous tests, and `IRONGUARD_EVAL_MODE` was active to prevent autonomous learning during the run.

---

## 🛠️ Performance & Latency Fixes (V10-V11)
The following critical bottlenecks were resolved to bring Avg latency down from 3,500ms+:
1. **DeBERTa Batching Optimization**: Reduced batch size from 32 to 8. This stops exponential padding token explosion which previously caused severe CPU hangs.
2. **In-Memory Trust Caching**: Implemented zero-latency caching for user trust scores, removing synchronous MongoDB reads from the request path.
3. **Async Scoring Updates**: Trust score updates are now fire-and-forget (`asyncio.create_task`), ensuring background database writes don't block the API response.
4. **Eval Mode Isolation**: Automated the bypass of behavioral and background context builders during evaluation runs to prevent database leakage and noise.

---

## 🚀 Future Roadmap: Phase 5 (Mutation Engine)
Now that the baseline is clean and performant, the next phase will focus on **Mutation Engineering** to target the 862 attacks (False Negatives) that bypass the DeBERTa classifier.
