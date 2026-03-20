# IronGuard Detection Layers

IronGuard uses a **Hybrid Multi-Layer Detection Strategy** to identify and block security threats in real-time. The pipeline is orchestrated by the Decision Engine v2 for maximum protection and low latency.

## Layer 0: Ingress Normalizer (NFKC)
The first step for every prompt entering the gateway.
- **Normalization**: Applies Unicode NFKC (Normalization Form Compatibility Composition) to flatten the text.
- **Security**: Protects against homoglyph attacks (e.g., using a Cyrillic 'а' instead of 'a'), hidden control characters, and encoding bypasses that aim to slip past regex patterns.

---

## Layer 1: Pattern Detector (Regex & Fuzzy Match)
Managed by `app/threat_detection/pattern.py`.
- **Comprehensive Library**: 150+ regex patterns covering Prompt Injection, System Prompt Leak, and Jailbreaks.
- **Hard Blocks**: Critical categories (Violence, Sexual Content, etc.) trigger an immediate 100/100 risk score and skip further processing.

---

## Layer 2: Semantic Analyzer (Vector Similarity)
Managed by `app/threat_detection/semantic.py`.
- **Vector Search**: Compares prompts against a "Threat Gallery" stored in ChromaDB using `all-MiniLM-L6-v2` embeddings.
- **Dynamic Thresholding**: Uses distance-based scoring to flag novel variations of known attacks.

---

## Layer 3: Intent Classifier (Contextual AI Layer)
Managed by `app/threat_detection/intent_classifier.py`.
- **Transformer-based**: Utilizes a `protectai/deberta-v3-base-prompt-injection-v2` model.
- **Contextual Awareness**: Analyzes underlying intent rather than just keywords, catching roleplay, social engineering, and indirect injections.
- **Confidence Calibration**: Scores from the classifier are mapped through a non-linear scaling function to ensure high-confidence threats are weighted appropriately.

---

## Layer 4: Fingerprinting Engine (MOD-3) — 100% Local
Managed by `app/fingerprinting/`.
- **Exact & Near-Match**: 
  - **SimHash**: Handles minor character variations (e.g., "Hello" vs "Hell0").
  - **MinHash LSH**: High-recall overlap detection for long, complex jailbreak payloads.
- **Autonomous Learning (Privacy First)**: New malicious prompts identified by other layers (with 80+ risk score) are automatically sanitized via **MOD-5 PII Redactor**. This process is **100% Local (Regex/Rule-based)**. No LLM call is made during the learning phase, ensuring zero data leakage and zero extra cost.

---

## The Weighting System (Decision Engine v2)

The **Risk Scorer** incorporates a sophisticated weighted aggregation of all detection signals. The final score is not just a sum, but a calibrated reputation signal.

| Signal | Base Weight | Multiplier | Dynamic Max |
| :--- | :--- | :--- | :--- |
| **Regex Hard Block** | 100 | x1.0 | 100 |
| **Intent Classifier (Malicious)** | 65 | x1.2 | 95 |
| **Fingerprint Match (LSH)** | 45 | x1.1 | 85 |
| **Semantic Similarity (Chroma)** | 35 | x1.0 | 75 |
| **User History Penalty** | +15 | x1.0 | +30 |

### Classification Thresholds:
- **0–29**: `Safe` (Passes to LLM Proxy Layer).
- **30–59**: `Suspicious` (Triggers MOD-4 Semantic Sanitization).
- **60–100**: `Malicious` (Blocked immediately via 403 response).

### The "Shield" Mechanism
If any layer reports a 100% confidence "Hard Block" (e.g., a regex for the internal system prompt), the Decision Engine enters **Emergency Block Mode**, skipping all other calculations to minimize latency and ensure zero-day protection.
