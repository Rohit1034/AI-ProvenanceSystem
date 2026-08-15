# Threat Model

## Scope

This document covers threats to the Image Provenance System's ability to correctly classify image provenance. It does not cover general application security (covered in docs/security.md).

## Threat Categories

### 1. Metadata Manipulation

**Severity: Medium**

| Attack | Description | Mitigation |
|---|---|---|
| Metadata stripping | Remove all EXIF/XMP/IPTC | Treat absent metadata as inconclusive, not proof of anything |
| Metadata forgery | Add fake camera EXIF to AI image | Cross-reference metadata with forensic signals; flag inconsistencies |
| Timestamp manipulation | Alter creation/modification dates | Note timestamps as evidence, not proof |
| Software tag forgery | Add/change software signatures | Use as one signal among many; never rely solely on metadata |

### 2. Re-encoding Attacks

**Severity: Medium**

| Attack | Description | Mitigation |
|---|---|---|
| Format conversion | JPEG → PNG → JPEG to destroy forensic signals | Track format conversion indicators; note limitations |
| Quality reduction | Heavy JPEG compression to mask artifacts | Compression analysis; note when quality is suspiciously low |
| Screenshot laundering | Screenshot of AI image to create "real" capture | Note screenshot indicators; warn about this limitation |
| Social media compression | WhatsApp/Instagram compression pipeline | Track compression signatures; note evidence degradation |

### 3. Geometric Manipulation

**Severity: Low**

| Attack | Description | Mitigation |
|---|---|---|
| Cropping | Remove watermark/C2PA regions | C2PA content binding detects this; note broken bindings |
| Resizing | Degrade resolution-dependent signals | Multi-scale analysis; note when resolution is suspiciously low |
| Rotation/flipping | Alter pixel arrangement | EXIF orientation analysis; invariant features |

### 4. Adversarial ML Attacks

**Severity: High**

| Attack | Description | Mitigation |
|---|---|---|
| Adversarial perturbation | Pixel-level noise to fool classifier | Ensemble models; adversarial training; confidence thresholds |
| Style transfer | Make AI images look more "photographic" | Multi-signal approach; don't rely solely on ML |
| Generator evolution | New AI models produce different artifacts | Regular model retraining; cross-generator evaluation |
| Training data poisoning | Compromise training pipeline | Dataset versioning; integrity verification; holdout validation |

### 5. Provenance Attacks

**Severity: Critical**

| Attack | Description | Mitigation |
|---|---|---|
| C2PA stripping | Remove C2PA manifest from file | Detect missing provenance; note as suspicious if format typically has it |
| Fake C2PA | Create forged C2PA manifest | Certificate chain validation; trust anchor verification |
| Watermark removal | Remove or degrade embedded watermarks | Robustness testing; note detection confidence |
| Watermark transplant | Copy watermark from one image to another | Content binding verification; forensic consistency checks |

### 6. System Attacks

**Severity: High**

| Attack | Description | Mitigation |
|---|---|---|
| Malformed files | Exploit image parser vulnerabilities | Input validation; sandboxed processing; Pillow safety limits |
| Decompression bomb | Pixel bomb / zip bomb in image | MAX_IMAGE_PIXELS limit; file size limits |
| Resource exhaustion | Upload many large files | Rate limiting; queue management; file size limits |
| Path traversal | Malicious filenames | Filename sanitization; never use user filenames for storage |

## Assumptions

1. Image parsers (Pillow, exifread) are reasonably secure but may have vulnerabilities
2. C2PA certificate chains from major providers are trustworthy
3. Attackers have access to all major AI generators
4. Sophisticated attackers can chain multiple evasion techniques
5. No detection system is 100% accurate — honest uncertainty is required

## Unmitigated Risks

- **Metadata-stripped, re-encoded AI images with no watermark**: If all provenance signals are removed and the ML model is uncertain, the system must return "inconclusive" rather than a false classification
- **Novel generators**: Models not in the training set will produce unpredictable classifier behavior
- **Sophisticated multi-step laundering**: Camera photo → AI edit → screenshot → social media → download creates a provenance chain that may be unrecoverable
