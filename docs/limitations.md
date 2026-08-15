# Limitations

## What This System Cannot Do

### Detection Limitations

1. **Cannot prove an image is human-created.** Absence of AI signals is not proof of human origin. The system can only report that no AI evidence was found.

2. **Cannot detect all AI generators.** New models emerge continuously. The ML classifier is trained on a finite set of generators and may not recognize output from unseen models.

3. **Cannot guarantee watermark detection.** Watermarks can be degraded by compression, resizing, cropping, and format conversion. A negative watermark result does not prove absence of AI generation.

4. **Cannot recover stripped metadata.** If EXIF/XMP/IPTC data has been removed, that information is permanently lost. The system notes the absence but cannot reconstruct it.

5. **Cannot distinguish all editing types.** The boundary between "conventional editing" and "AI-assisted editing" is increasingly blurred. A Photoshop file may contain AI-generated content via plugins.

### False Positive Scenarios

- **HDR/computational photography**: Modern smartphone cameras use AI-based processing (Night Sight, Deep Fusion) that may trigger AI detection
- **Heavy post-processing**: Extensive Lightroom/Photoshop work can introduce artifacts that resemble AI generation
- **Upscaling**: Traditional upscaling algorithms may be flagged by AI-edit detectors
- **Stock photo processing**: Watermark removal, color grading, and template compositing may trigger manipulation detection

### False Negative Scenarios

- **Screenshot laundering**: Taking a screenshot of an AI image creates a new "device capture" with screen metadata
- **Social media round-trip**: Upload to Instagram/WhatsApp → download strips metadata and re-encodes
- **Print-and-scan**: Physical printing and re-scanning destroys all digital provenance
- **Metadata forgery**: Adding fake camera EXIF to an AI-generated image

### Format Limitations

- HEIC/HEIF: Not currently supported (planned)
- AVIF: Not currently supported (planned)
- RAW formats: Not analyzed (CR2, NEF, ARW, etc.)
- Video frames: Not supported
- SVG/vector: Not applicable

### Provider Coverage Gaps

Most AI providers do not offer public watermark detection APIs. Current coverage:
- **C2PA verification**: Supported for any C2PA-compliant image
- **SynthID**: Not yet implemented (requires Google API access)
- **OpenAI watermarks**: Detection not publicly available
- **Midjourney**: No public detection mechanism
- **Stable Diffusion**: No built-in watermark
- **Adobe Firefly**: C2PA-based (covered by C2PA analyzer)

### Confidence Calibration

- ML model confidence scores are not calibrated in Phase 1
- Reported confidence reflects evidence availability, not prediction accuracy
- Actual precision/recall metrics will be established after ML training (Phase 4)
