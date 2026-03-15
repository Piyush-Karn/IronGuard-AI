# IronGuard Detection Layers

IronGuard uses a **Hybrid Multi-Layer Detection Strategy** to identify and block security threats in real-time. This document deep-dives into each of the three active security layers.

## Layer 1: Pattern Detector (Regex & Fuzzy Match)

The Pattern Detector is the first line of defense. It uses high-speed string matching to catch deterministic attack signatures.

### Key Features:
- **Comprehensive Regex Library**: Over 150+ regex patterns covering Prompt Injection, System Prompt Leak, Jailbreaks, Malware, Violence, and more.
- **Fuzzy Matching**: Uses the `rapidfuzz` library to catch permutations and typos (e.g., "Sysem prromt").
- **Multi-Language Support**: Detection patterns for common injection strings in multiple languages.
- **Hard Blocks**: Critical categories (like Violence, Weapons, or Sexual Content) are flagged for an immediate 100/100 risk score and blocked without further evaluation.

### Implementation:
`app/threat_detection/pattern.py`

---

## Layer 2: Semantic Analyzer (Vector Similarity)

The Semantic Analyzer catches contextual attacks that don't match specific strings but share the same *meaning* as previously known attacks.

### Key Features:
- **Vector Search**: Compares the incoming prompt against a "Threat Gallery" stored in ChromaDB.
- **High-Volume Dataset**: Initialized with ~60,000 unique attack vectors from Hugging Face (`advbench`, `hh-rlhf`, `JBB-Behaviors`).
- **Explainable Results**: Returns the `attack_type` of the nearest neighbor to help administrators understand the nature of the threat.
- **Batched Ingestion**: Uses a safe, batched encoding strategy to initialize the database efficiently during startup.

### Implementation:
`app/threat_detection/similarity.py`
`seed_data/init_dataset.py`

---

## Layer 3: Intent Classifier (Contextual AI Layer)

The Intent Classifier is the most advanced layer, using a dedicated transformer model to evaluate the user's underlying intent.

### Key Features:
- **Deep Contextual Understanding**: Can detect sophisticated "Roleplay" attacks (e.g., "Bob and Alice" scenarios) that might look like harmless stories to simpler layers.
- **Optimized Performance**: Uses a quantized `deberta-v3-base` model trained explicitly for prompt injection detection.
- **Async Execution**: Runs in a non-blocking thread so that the event loop remains responsive.
- **High Sensitivity**: Provides a confidence score (0-100%) that acts as a strong weight in the final risk calculation.

### Implementation:
`app/threat_detection/intent_classifier.py`

---

## The Weighting System

The **Risk Scorer** aggregates signals from all layers into a single score:

| Signal | Weight |
| :--- | :--- |
| **Regex Pattern Match** | +60 |
| **Intent Classifier (Positive)** | +50 |
| **Semantic Similarity Hit** | +30 |
| **Guardrail Integration Fail** | +30 |

### Classification Thresholds:
- **0–29**: `Safe` (Passes directly to LLM).
- **30–59**: `Suspicious` (Prompt is sanitized before being sent).
- **60–100**: `Malicious` (Request is blocked immediately).
