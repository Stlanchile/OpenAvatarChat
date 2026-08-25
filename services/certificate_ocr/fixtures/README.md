# Qualification fixtures

Production qualification fixtures are not committed in Milestone 6A because no
backend/model environment is provisioned in this checkout.

Provide only synthetic, redacted, or otherwise approved non-sensitive JPEGs and
a manifest with schema `oac.ocr-fixtures.v1`. The harness requires coverage for
Simplified Chinese, Latin, mixed text, punctuation, ordinary digits,
orientation-normalized input, low-quality decodable input, and at least one
representative 1920x1080 frame. A
perspective/skew category may be added when a suitable fixture exists.

Each fixture records its exact SHA-256, canonical dimensions, ordered expected
text spans, normalized four-point polygons, and polygon tolerance. The harness
reports booleans and output hashes; it does not print recognized text.
