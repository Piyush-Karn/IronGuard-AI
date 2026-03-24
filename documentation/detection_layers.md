# 🔍 IronGuard Detection Layers

> IronGuard uses a **Hybrid Multi-Layer Detection Strategy** to identify and block security threats in real-time. The pipeline is orchestrated by the **Decision Engine v2** for maximum protection and minimum latency.

---

## Pipeline Overview

```
Incoming Prompt
      │
      ▼
┌─────────────────────────┐
│  Layer 0: NFKC Normalizer│  ← Homoglyph & encoding bypass protection
└────────────┬────────────┘
             │
      ┌──────┴──────────────────────────────┐
      │         Parallel Execution          │
      ├──────────┬──────────┬───────────────┤
      ▼          ▼          ▼               ▼
  Layer 1     Layer 2    Layer 3        Layer 4
  Pattern     Semantic    Intent        Fingerprint
  Detector    Analyzer   Classifier     Engine
      │          │          │               │
      └──────────┴──────────┴───────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │  Risk Scorer  │
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │Decision Engine│
                    └───────┬───────┘
                    ┌───────┴──────────┐
              Block / Sanitize / Pass
```

---

## Layer 0 — Ingress Normalizer (NFKC)

The **first step** for every prompt entering the gateway.

| Property | Detail |
|----------|--------|
| **Method** | Unicode NFKC (Normalization Form Compatibility Composition) |
| **Protects Against** | Homoglyph attacks (e.g., Cyrillic `а` instead of Latin `a`), hidden control characters, encoding bypasses |

> **Example**: `Wrіte a scrіpt` (Cyrillic `і`) → normalized to → `Write a script` → caught by Layer 1

---

## Layer 1 — Pattern Detector (Regex & Fuzzy Match)

**File**: `app/threat_detection/pattern.py`

| Property | Detail |
|----------|--------|
| **Coverage** | 150+ regex patterns for Prompt Injection, System Prompt Leak, and Jailbreaks |
| **Hard Blocks** | Critical categories (Violence, Sexual Content, etc.) immediately return `risk_score: 100` and skip all further processing |

---

## Layer 2 — Semantic Analyzer (Vector Similarity)

**File**: `app/threat_detection/semantic.py`

| Property | Detail |
|----------|--------|
| **Model** | `all-MiniLM-L6-v2` (384-dimensional embeddings) |
| **Database** | ChromaDB "Threat Gallery" |
| **Strategy** | Dynamic distance-based thresholding to flag novel variations of known attacks |

---

## Layer 3 — Intent Classifier (Contextual AI)

**File**: `app/threat_detection/intent_classifier.py`

| Property | Detail |
|----------|--------|
| **Model** | `protectai/deberta-v3-base-prompt-injection-v2` |
| **Strength** | Analyzes underlying *intent*, not just keywords — catches roleplay, social engineering, indirect injections |
| **Scoring** | Non-linear confidence mapping ensures high-confidence threats are weighted appropriately |

---

## Layer 4 — Fingerprinting Engine / MOD-3

**File**: `app/fingerprinting/`

| Algorithm | Use Case |
|-----------|----------|
| **SimHash** (64-bit) | Handles minor character variations (e.g., `Hello` vs `Hell0`) via Hamming distance |
| **MinHash LSH** (128 perms) | High-recall overlap detection for long, complex jailbreak payloads |

### 🧬 Autonomous Learning (Privacy-First)

When a novel threat is detected with `risk_score > 80` and **no existing fingerprint**:

1. **MOD-5 PII Redactor** strips all personal data — **100% locally, no LLM call**
2. A **SimHash** + **MinHash** signature is generated
3. The signature is appended to `fingerprint_db.json` via **hot-reload** (no restart needed)
4. Future identical/similar (≥90%) prompts are blocked in **< 2ms**

---

## ⚖️ Weighting System (Decision Engine v2)

| Signal | Base Weight | Multiplier | Dynamic Max |
|--------|:-----------:|:----------:|:-----------:|
| Regex Hard Block | 100 | ×1.0 | **100** |
| Intent Classifier (Malicious) | 65 | ×1.2 | **95** |
| Fingerprint Match (LSH) | 45 | ×1.1 | **85** |
| Semantic Similarity (ChromaDB) | 35 | ×1.0 | **75** |
| User History Penalty | +15 | ×1.0 | **+30** |

### Classification Thresholds

| Score Range | Classification | Action |
|:-----------:|:--------------:|--------|
| **0 – 29** | ✅ `Safe` | Passes to LLM Proxy (MOD-1) |
| **30 – 59** | ⚠️ `Suspicious` | Triggers MOD-4 Semantic Sanitization |
| **60 – 100** | 🚫 `Malicious` | Blocked immediately (403 response) |

### 🛡️ Emergency Block Mode ("The Shield")

If **any layer** reports a `100%` confidence Hard Block (e.g., a regex match on the internal system prompt), the Decision Engine enters **Emergency Block Mode** — skipping all remaining calculations to minimize latency.

---

<div align="right"><a href="../README.md">← Back to README</a></div>