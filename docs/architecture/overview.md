# Architecture Overview

## System Design

The Image Provenance System is an evidence-fusion architecture. Rather than relying on a single AI classifier, it combines multiple independent analysis signals into a weighted evidence chain.

### Core Principle

Every claim about an image must be traceable to specific evidence. The system distinguishes between:

1. **Provenance evidence** — cryptographic proof (C2PA, verified watermarks)
2. **Metadata evidence** — software signatures, camera data, timestamps
3. **Forensic evidence** — compression artifacts, noise patterns, structural anomalies
4. **ML evidence** — classifier predictions (probabilistic, not deterministic)

These layers have different reliability profiles and must never be conflated.

## Component Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Frontend (React)                   │
│  Upload → Status → Forensic Report Dashboard         │
└──────────────────────┬──────────────────────────────┘
                       │ HTTP/REST
┌──────────────────────┴──────────────────────────────┐
│                 FastAPI Backend                       │
│                                                      │
│  ┌─────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │   API   │→ │   Analysis   │→ │   Evidence     │  │
│  │ Routes  │  │   Service    │  │   Fusion       │  │
│  └─────────┘  └──────┬───────┘  └────────────────┘  │
│                      │                               │
│  ┌───────────────────┴─────────────────────────────┐ │
│  │              Analysis Pipeline                   │ │
│  │                                                  │ │
│  │  FileValidator → HashGenerator → FormatAnalyzer  │ │
│  │  → MetadataExtractor → C2PAAnalyzer              │ │
│  │  → [WatermarkDetector] → [ForensicsEngine]       │ │
│  │  → [MLClassifier]                                │ │
│  └──────────────────────────────────────────────────┘ │
│                                                      │
│  ┌──────────┐  ┌───────────┐  ┌─────────────────┐   │
│  │ Storage  │  │ Database  │  │   Model         │   │
│  │ Backend  │  │ (Postgres)│  │   Registry      │   │
│  └──────────┘  └───────────┘  └─────────────────┘   │
└──────────────────────────────────────────────────────┘
```

## Data Flow

1. **Ingestion**: Image uploaded → validated → hashed → stored immutably
2. **Analysis**: Pipeline runs each analyzer sequentially, collecting AnalyzerResult objects
3. **Fusion**: All analyzer results combined into a classification with confidence score
4. **Report**: Structured forensic report generated with full evidence chain

## Key Design Decisions

- **Analyzers are independent**: Each returns structured evidence without seeing other analyzers' output
- **Evidence, not conclusions**: Analyzers produce findings; only the fusion engine classifies
- **Graceful degradation**: If an analyzer fails or isn't available, remaining analyzers still run
- **Original preservation**: Uploaded bytes are never modified; analysis runs on a stored copy
- **Honest uncertainty**: System reports "inconclusive" rather than fabricating confidence
