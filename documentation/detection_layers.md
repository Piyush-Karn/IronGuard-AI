# IronGuard Detection Layers

IronGuard uses a **Hybrid Multi-Layer Detection Strategy** to identify and block security threats in real-time. The pipeline is orchestrated by the Decision Engine v2 for maximum protection and low latency.

## Layer 0: Ingress Normalizer (NFKC)
The first step for every prompt entering the gateway.
- **Normalization**: Applies Unicode NFKC (Normalization Form Compatibility Composition) to flatten the text.
- **Security**: Protects against homoglyph attacks (e.g., using a Cyrillic 'а' instead of 'a'), hidden control characters, and encoding bypasses that aim to slip past regex patterns.

---

## Layer 1: Pattern Detector (Regex & Fuzzy Match)
Managed by `app/threat_detection/pattern.py`.
- **Comprehensive Library**: 150+ regex patterns covering Prompt Injection, System Prompt Leak, Jailbreaks, and Maltitude of other categories.
- **Hard Blocks**: Critical categories (Violence, Sexual Content, etc.) trigger an immediate 100/100 risk score.

---

## Layer 2: Semantic Analyzer (Vector Similarity)
Managed by `app/threat_detection/similarity.py`.
- **Vector Search**: Compares prompts against a "Threat Gallery" stored in ChromaDB.
- **High-Volume Dataset**: Initialized with ~60,000 attack vectors (`advbench`, `hh-rlhf`).

---

## Layer 3: Intent Classifier (Contextual AI Layer)
Managed by `app/threat_detection/intent_classifier.py`.
- **Context Awareness**: A dedicated transformer model (`protectai/deberta-v3-base`) that understands the underlying intent.
- **Roleplay Detection**: Specifically detects sophisticated jailbreaks that use roleplay framing.

---

## Layer 4: Fingerprinting Engine (MOD-3)
Managed by `app/fingerprinting/`.
- **Cascade Detection**:
  - **SimHash**: sub-ms Hamming distance check using XOR bits.
  - **MinHash LSH**: High-recall overlaps detection.
- **Fast Match**: Instantly catches known adversarial strings from `fingerprint_db.json`.

---

## The Weighting System

The **Risk Scorer** aggregates signals from all layers into a single score:

| Signal | Weight | Type |
| :--- | :--- | :--- |
| **Regex Hard Block** | 100 | Blocking |
| **Intent Classifier (Positive)** | +50 | Dynamic |
| **Fingerprint Match (MOD-3)** | +30 | Static |
| **Semantic Similarity Hit** | +30 | Contextual |

### Classification Thresholds:
- **0–29**: `Safe` (Passes to LLM Proxy).
- **30–59**: `Suspicious` (Triggers MOD-4 Semantic Sanitization).
- **60–100**: `Malicious` (Blocked immediately).
