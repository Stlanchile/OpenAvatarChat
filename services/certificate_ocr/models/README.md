# Pre-provisioned OCR artifacts

This directory intentionally contains no production OCR model or qualification
record. Do not download models at runtime.

After an explicit qualification decision, provision:

- `model_manifest.json`;
- the exact PP-OCRv6 medium detector and recognizer directories;
- every source/configuration/dictionary artifact named by the manifest;
- the canonical qualification record named by the manifest;
- one non-sensitive warmup JPEG named by the manifest.

The identity uses model roles `detector` and `recognizer`; their model names
must equal the manifest directory names. The sidecar verifies every declared
file SHA-256, both deterministic model-directory digests, the dictionary
binding, and the selected identity in the qualification record before
importing PaddleOCR. Missing, extra, mismatched, or unqualified material leaves
OCR unavailable.
