# Evidence Model

## Evidence Categories

### 1. Provenance Evidence (highest weight)
- **C2PA manifests**: Cryptographically signed provenance claims
- **Verified watermarks**: SynthID, provider-specific embedded signals
- Weight: High — these are designed specifically to prove provenance

### 2. Metadata Evidence (medium weight)
- **Camera signatures**: Make/model/lens/exposure from EXIF
- **Software signatures**: Photoshop, DALL-E, Midjourney, etc.
- **Timestamps**: Creation, modification, digitization dates
- **GPS data**: Location metadata (presence/absence only)
- Weight: Medium — easily forged or stripped, but informative when present

### 3. Forensic Evidence (medium weight)
- **Compression artifacts**: Double JPEG compression, quantization tables
- **Noise patterns**: Sensor noise consistency, PRNU
- **Structural anomalies**: Resampling, copy-move, edge inconsistencies
- Weight: Medium — requires careful interpretation, prone to false positives

### 4. ML Evidence (variable weight)
- **AI-generation probability**: Classifier output
- **AI-edit probability**: Edit detection model output
- **Provider classification**: Which generator/editor was used
- Weight: Variable — depends on model calibration and validation

### 5. Similarity Evidence (low weight, future)
- **Perceptual hash matches**: Near-duplicate detection
- **Reverse image search**: Finding the original or earlier versions
- Weight: Low — indirect evidence, requires external databases

## Classification Taxonomy

| Classification | Required Evidence |
|---|---|
| `VERIFIED_AI_PROVENANCE` | Valid C2PA with AI action OR verified AI watermark |
| `LIKELY_AI_GENERATED` | Strong ML + consistent metadata (no camera EXIF) |
| `LIKELY_AI_EDITED` | AI edit signals + original image evidence |
| `CONVENTIONALLY_EDITED` | Editing software signatures, compression artifacts |
| `LIKELY_ORIGINAL` | Camera metadata, consistent noise, no edit signals |
| `MIXED_PROVENANCE` | Multiple conflicting signals |
| `INCONCLUSIVE` | Insufficient evidence for any classification |

## Confidence Calibration

Raw model probabilities are NOT confidence scores. The system must:

1. Calibrate model outputs against held-out validation sets
2. Account for base rates in the deployment population
3. Adjust for evidence availability (more analyzers = higher potential confidence)
4. Report separate scores: model score, system confidence, provenance certainty

## Fusion Strategy

Phase 1 (current): Rule-based fusion with priority ordering.
Phase 6 (planned): Calibrated stacking or Bayesian evidence combination.

Priority ordering:
1. Cryptographic provenance (C2PA) overrides probabilistic signals
2. Verified watermarks are strong positive evidence
3. Metadata signatures inform but don't determine
4. ML evidence contributes when provenance is absent
5. Forensic signals are supporting evidence

The fusion engine must never produce a classification that contradicts verified provenance.
