export interface PerceptualHash {
  hash_algorithm: string;
  hash_value: string;
}

export interface EvidenceResultData {
  analyzer_name: string;
  analyzer_version: string;
  status: string;
  confidence: number | null;
  findings: Record<string, unknown>[] | null;
  limitations: string[] | null;
  duration_ms: number | null;
  created_at: string;
}

export interface AnalysisSummary {
  analysis_id: string;
  status: string;
  classification: string | null;
  overall_confidence: number | null;
  original_sha256: string;
  file_size: number;
  mime_type: string;
  detected_format: string;
  width: number | null;
  height: number | null;
  created_at: string;
  completed_at: string | null;
}

export interface AnalysisDetail extends AnalysisSummary {
  bit_depth: number | null;
  color_mode: string | null;
  color_profile: string | null;
  compression_info: Record<string, unknown> | null;
  analysis_version: string;
  software_version: string;
  model_versions: Record<string, string> | null;
  error_message: string | null;
  evidence_results: EvidenceResultData[];
}

export interface ImageInfo {
  sha256: string;
  file_size: number;
  mime_type: string;
  format: string;
  width: number | null;
  height: number | null;
  bit_depth: number | null;
  color_mode: string | null;
  color_profile: string | null;
  compression_info: Record<string, unknown> | null;
  perceptual_hashes: PerceptualHash[];
}

export interface C2PAInfo {
  present: boolean;
  valid: boolean | null;
  trusted: boolean | null;
  signer: string | null;
  claim_generator: string | null;
  actions: Record<string, unknown>[];
  ingredients: Record<string, unknown>[];
  validation_errors: string[];
  trust_signals: string[];
}

export interface WatermarkResult {
  provider: string;
  watermark_type: string;
  detected: boolean;
  confidence: number;
  detector_version: string;
  limitations: string[];
  evidence: Record<string, unknown>;
}

export interface ProvenanceSection {
  c2pa: C2PAInfo;
  metadata: Record<string, unknown>;
  watermarks: WatermarkResult[];
}

export interface ForensicsSection {
  compression: Record<string, unknown>;
  ela: Record<string, unknown>;
  noise: Record<string, unknown>;
  resampling: Record<string, unknown>;
  copy_move: Record<string, unknown>;
  statistics: Record<string, unknown>;
}

export interface MLSection {
  ai_generated: number | null;
  ai_edited: number | null;
  conventional_edit: number | null;
  provider_prediction: string | null;
  provider_confidence: number | null;
  model_name: string | null;
  model_version: string | null;
  status: string;
}

export interface EvidenceItem {
  source: string;
  category: string;
  description: string;
  confidence: number | null;
  supports: string | null;
}

export interface ForensicReport {
  analysis_id: string;
  classification: string | null;
  overall_confidence: number | null;
  image_info: ImageInfo;
  provenance: ProvenanceSection;
  forensics: ForensicsSection;
  ml: MLSection;
  regions: Record<string, unknown>[];
  evidence_chain: EvidenceItem[];
  limitations: string[];
}

export interface HealthResponse {
  status: string;
  version: string;
  analyzers: Record<string, string>;
}

export type ClassificationType =
  | "verified_ai_provenance"
  | "likely_ai_generated"
  | "likely_ai_edited"
  | "conventionally_edited"
  | "likely_original"
  | "mixed_provenance"
  | "inconclusive";

export const CLASSIFICATION_LABELS: Record<ClassificationType, string> = {
  verified_ai_provenance: "Verified AI Provenance",
  likely_ai_generated: "Likely AI-Generated",
  likely_ai_edited: "Likely AI-Edited",
  conventionally_edited: "Conventionally Edited",
  likely_original: "Likely Original",
  mixed_provenance: "Mixed Provenance",
  inconclusive: "Inconclusive",
};
