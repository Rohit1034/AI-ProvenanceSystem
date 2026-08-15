# Image Provenance System

A production-oriented platform for analyzing uploaded images and determining their provenance and manipulation history. Built as an evidence-fusion system that combines metadata forensics, C2PA provenance verification, format analysis, and (future) ML-based AI detection.

## Architecture

```
IMAGE UPLOAD
    ↓
FILE VALIDATION → magic bytes, MIME, size, decompression bomb check
    ↓
HASH GENERATION → SHA-256, average_hash, phash, dhash, whash
    ↓
FORMAT ANALYSIS → JPEG segments, PNG chunks, WebP RIFF, quantization tables
    ↓
METADATA EXTRACTION → EXIF, XMP, IPTC, software signatures, camera info
    ↓
C2PA ANALYSIS → manifest detection, signature validation, provenance chain
    ↓
EVIDENCE FUSION → combine all signals into classification + confidence
    ↓
FORENSIC REPORT → structured JSON with evidence chain and limitations
```

### Classification Taxonomy

| Category | Meaning |
|---|---|
| `VERIFIED_AI_PROVENANCE` | Cryptographic proof of AI involvement (C2PA, verified watermark) |
| `LIKELY_AI_GENERATED` | Strong evidence of full AI generation |
| `LIKELY_AI_EDITED` | Strong evidence of AI-assisted editing |
| `CONVENTIONALLY_EDITED` | Evidence of traditional digital editing |
| `LIKELY_ORIGINAL` | Evidence suggests unmodified camera/device capture |
| `MIXED_PROVENANCE` | Multiple provenance signals detected |
| `INCONCLUSIVE` | Insufficient evidence for classification |

## Quick Start

```bash
# Clone and configure
cp .env.example .env

# Start with Docker
docker compose up --build

# Access
# Frontend: http://localhost
# Backend API: http://localhost:8000
# API docs: http://localhost:8000/docs
```

## Development Setup

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt

# Start PostgreSQL (Docker or local)
docker compose up postgres redis -d

# Run the API server
uvicorn backend.app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The Vite dev server proxies `/api` requests to `localhost:8000`.

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/analyze` | Upload image for analysis |
| `GET` | `/api/v1/analysis/{id}` | Get analysis details |
| `GET` | `/api/v1/analysis/{id}/report` | Get full forensic report |
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/version` | Version information |

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://...` | PostgreSQL connection |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `STORAGE_BACKEND` | `local` | Storage backend (local/s3) |
| `STORAGE_LOCAL_PATH` | `./storage` | Local storage directory |
| `MAX_UPLOAD_SIZE_MB` | `100` | Maximum upload size |
| `LOG_LEVEL` | `INFO` | Logging level |
| `CORS_ORIGINS` | `[...]` | Allowed CORS origins |

## Phase Roadmap

- [x] **Phase 1** — Evidence Foundation: upload, validation, hashing, format analysis, metadata, C2PA, evidence fusion, API, frontend
- [ ] **Phase 2** — Provenance & Watermark Layer: provider registry, watermark detectors, SynthID
- [ ] **Phase 3** — Classical Forensics: compression analysis, noise, resampling, copy-move
- [ ] **Phase 4** — ML Baseline: AI-generated classifier, dataset pipeline, training
- [ ] **Phase 5** — AI Edit Detection: paired datasets, patch-based analysis, heatmaps
- [ ] **Phase 6** — Evidence Fusion v2: Bayesian fusion, calibrated stacking
- [ ] **Phase 7** — Production Hardening: auth, rate limiting, GPU workers, monitoring

## Security

- All uploaded images treated as untrusted input
- Magic byte and MIME validation
- Decompression bomb protection
- Path traversal prevention
- Filename sanitization
- GPS coordinates extracted but never logged
- No execution of metadata contents

## Current Limitations

- **No ML detection**: Classification relies on metadata and provenance signals only
- **No watermark detection**: SynthID, C2PA watermarks, and provider-specific watermarks not yet implemented
- **No classical forensics**: Noise analysis, copy-move, resampling detection not yet implemented
- **No region-level analysis**: Heatmaps and localization not yet available
- **No HEIC/AVIF support**: Only JPEG, PNG, WebP, TIFF, BMP currently supported
- **Synchronous processing**: Analysis runs in the request thread (no background workers yet)
- Absence of AI signals does NOT mean the image is human-created
- Metadata can be stripped or forged

## License

Proprietary. All rights reserved.
