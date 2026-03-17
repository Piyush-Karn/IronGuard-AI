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
- **Contextual Awareness**: Analyzes underlying intent rather than just keywords, catching roleplay and social engineering.

---

## Layer 4: Fingerprinting Engine (MOD-3)
Managed by `app/fingerprinting/`.
- **Exact & Near-Match**:
  - **SimHash**: Handles minor character variations.
  - **MinHash LSH**: High-recall overlap detection.
- **Self-Learning**: New malicious prompts identified by other layers are automatically learned (redacted) into the fingerprint DB.

---

## The Weighting System

The **Risk Scorer** aggregates signals from all layers:

| Signal | Base Weight | Dynamic Max |
| :--- | :--- | :--- |
| **Regex Hard Block** | 100 | 100 |
| **Intent Classifier (Malicious)** | 60 | 90 |
| **Fingerprint Match (MOD-3)** | 40 | 80 |
| **Semantic Similarity Hit** | 35 | 70 |

### Classification Thresholds:
- **0–29**: `Safe` (Passes to LLM Proxy).
- **30–59**: `Suspicious` (Triggers MOD-4 Semantic Sanitization).
- **60–100**: `Malicious` (Blocked immediately).
