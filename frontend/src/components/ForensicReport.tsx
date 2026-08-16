import type { ForensicReport as Report } from "../types/analysis";
import ClassificationBadge from "./ClassificationBadge";
import ConfidenceIndicator from "./ConfidenceIndicator";
import EvidenceCard from "./EvidenceCard";
import MetadataViewer from "./MetadataViewer";
import ProvenanceTimeline from "./ProvenanceTimeline";
import {
  Shield,
  FileText,
  Hash,
  AlertTriangle,
  Download,
  Eye,
  Fingerprint,
  Cpu,
  BarChart3,
  Droplets,
} from "lucide-react";
import type { AnalysisDetail } from "../types/analysis";

interface Props {
  analysis: AnalysisDetail;
  report: Report;
}

export default function ForensicReportView({ analysis, report }: Props) {
  const handleDownloadJSON = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `forensic-report-${report.analysis_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-xs text-slate-500 uppercase tracking-wider mb-2">
              Image Forensic Analysis
            </h2>
            <div className="flex items-center gap-3 mb-3">
              <ClassificationBadge
                classification={report.classification}
                size="lg"
              />
            </div>
            <ConfidenceIndicator
              value={report.overall_confidence}
              label="Overall Confidence"
              size="lg"
            />
          </div>
          <button
            onClick={handleDownloadJSON}
            className="flex items-center gap-2 px-3 py-2 text-sm text-slate-400 hover:text-slate-200 bg-slate-700/50 hover:bg-slate-700 rounded-lg transition-colors"
          >
            <Download className="w-4 h-4" />
            JSON
          </button>
        </div>
      </div>

      {/* Image Info */}
      <Section icon={FileText} title="Image Information">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <InfoCell label="Format" value={report.image_info.format} />
          <InfoCell label="Dimensions" value={
            report.image_info.width && report.image_info.height
              ? `${report.image_info.width} x ${report.image_info.height}`
              : "Unknown"
          } />
          <InfoCell label="File Size" value={formatBytes(report.image_info.file_size)} />
          <InfoCell label="Color Mode" value={report.image_info.color_mode ?? "N/A"} />
          <InfoCell label="Bit Depth" value={report.image_info.bit_depth?.toString() ?? "N/A"} />
          <InfoCell label="Color Profile" value={report.image_info.color_profile ?? "N/A"} />
          <InfoCell label="MIME Type" value={report.image_info.mime_type} mono />
        </div>
      </Section>

      {/* Hashes */}
      <Section icon={Fingerprint} title="Integrity Hashes">
        <div className="space-y-2">
          <div className="flex gap-2">
            <span className="text-xs text-slate-500 w-16">SHA-256</span>
            <span className="text-xs font-mono text-slate-300 break-all">
              {report.image_info.sha256}
            </span>
          </div>
          {report.image_info.perceptual_hashes.map((h) => (
            <div key={h.hash_algorithm} className="flex gap-2">
              <span className="text-xs text-slate-500 w-16">{h.hash_algorithm}</span>
              <span className="text-xs font-mono text-slate-300">{h.hash_value}</span>
            </div>
          ))}
        </div>
      </Section>

      {/* C2PA Provenance */}
      <Section icon={Shield} title="Provenance (C2PA)">
        {report.provenance.c2pa.present ? (
          <div className="space-y-2">
            <StatusRow label="Present" value="Yes" positive />
            <StatusRow
              label="Valid"
              value={report.provenance.c2pa.valid ? "Yes" : "No"}
              positive={report.provenance.c2pa.valid ?? false}
            />
            <StatusRow
              label="Trusted"
              value={report.provenance.c2pa.trusted ? "Yes" : "No"}
              positive={report.provenance.c2pa.trusted ?? false}
            />
            {report.provenance.c2pa.signer && (
              <StatusRow label="Signer" value={report.provenance.c2pa.signer} />
            )}
            {report.provenance.c2pa.claim_generator && (
              <StatusRow label="Generator" value={report.provenance.c2pa.claim_generator} />
            )}
          </div>
        ) : (
          <p className="text-sm text-slate-500">
            No C2PA manifest found in this image
          </p>
        )}
      </Section>

      {/* Watermark Detection */}
      <Section icon={Droplets} title="Watermark Detection">
        {report.provenance.watermarks.length > 0 ? (
          <div className="space-y-3">
            {report.provenance.watermarks.map((w, i) => (
              <div key={i} className="bg-slate-700/30 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-2">
                  <span className={`inline-block w-2 h-2 rounded-full ${w.detected ? "bg-amber-400" : "bg-slate-500"}`} />
                  <span className="text-sm font-medium text-slate-200">
                    {w.provider} — {w.watermark_type}
                  </span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                  <StatusRow label="Detected" value={w.detected ? "Yes" : "No"} positive={w.detected} />
                  <InfoCell label="Confidence" value={`${(w.confidence * 100).toFixed(1)}%`} />
                  <InfoCell label="Detector" value={w.detector_version} mono />
                </div>
                {w.limitations.length > 0 && (
                  <div className="mt-2">
                    {w.limitations.map((lim, li) => (
                      <p key={li} className="text-xs text-slate-500 mt-1">{lim}</p>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-slate-500">
            No AI watermarks detected (SynthID, DWT, LSB, DCT)
          </p>
        )}
      </Section>

      {/* ML AI Detection */}
      <Section icon={Cpu} title="AI Detection (ML)">
        {report.ml.status === "not_implemented" || report.ml.status === "error" ? (
          <p className="text-sm text-amber-400/70">
            {report.ml.status === "error"
              ? "ML analysis encountered an error. Classification is based on metadata and provenance signals only."
              : "ML-based AI detection is not yet implemented. Classification is based on metadata and provenance signals only."}
          </p>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <ConfidenceIndicator value={report.ml.ai_generated} label="AI Generated" />
              <ConfidenceIndicator value={report.ml.ai_edited} label="AI Edited" />
              <ConfidenceIndicator value={report.ml.conventional_edit} label="Conv. Edit" />
            </div>
            {report.ml.model_name && (
              <div className="text-xs text-slate-500 mt-2">
                Model: {report.ml.model_name} v{report.ml.model_version}
              </div>
            )}
          </div>
        )}
      </Section>

      {/* Forensics Analysis */}
      <Section icon={BarChart3} title="Forensic Analysis">
        <div className="space-y-4">
          {/* ELA */}
          {report.forensics.ela && Object.keys(report.forensics.ela).length > 0 && (
            <div>
              <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-2">Error Level Analysis (ELA)</h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {(() => {
                  const gs = (report.forensics.ela as Record<string, unknown>)?.global_stats as Record<string, number> | undefined;
                  if (!gs) return null;
                  return (
                    <>
                      <InfoCell label="Mean Error" value={gs.mean_error?.toFixed(2) ?? "N/A"} />
                      <InfoCell label="Max Error" value={gs.max_error?.toFixed(2) ?? "N/A"} />
                      <InfoCell label="Std Dev" value={gs.std_error?.toFixed(2) ?? "N/A"} />
                      <InfoCell label="Quality" value={gs.quality_used?.toString() ?? "N/A"} />
                    </>
                  );
                })()}
              </div>
              {(() => {
                const ga = (report.forensics.ela as Record<string, unknown>)?.grid_analysis as Record<string, number> | undefined;
                if (!ga || !ga.suspicious_blocks) return null;
                return (
                  <p className="text-sm text-amber-400/80 mt-2">
                    {ga.suspicious_blocks} of {ga.total_blocks} blocks show anomalous error levels
                  </p>
                );
              })()}
            </div>
          )}

          {/* Statistics */}
          {report.forensics.statistics && Object.keys(report.forensics.statistics).length > 0 && (
            <div>
              <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-2">Image Statistics</h4>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                {(() => {
                  const stats = report.forensics.statistics as Record<string, unknown>;
                  return (
                    <>
                      <InfoCell label="Noise Level" value={(stats.noise_level as number)?.toFixed(3) ?? "N/A"} />
                      <InfoCell label="Laplacian Var" value={(stats.laplacian_variance as number)?.toFixed(2) ?? "N/A"} />
                      {(() => {
                        const sat = stats.saturation as Record<string, number> | undefined;
                        if (!sat) return null;
                        return <InfoCell label="Avg Saturation" value={sat.mean?.toFixed(4) ?? "N/A"} />;
                      })()}
                    </>
                  );
                })()}
              </div>
            </div>
          )}

          {/* PRNU / Sensor Noise */}
          {report.forensics.noise && Object.keys(report.forensics.noise).length > 0 && (
            <div>
              <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-2">Sensor Noise (PRNU)</h4>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                {(() => {
                  const ns = (report.forensics.noise as Record<string, unknown>)?.noise_stats as Record<string, unknown> | undefined;
                  if (!ns) return null;
                  return (
                    <>
                      <InfoCell label="Noise Variance" value={(ns.variance as number)?.toFixed(4) ?? "N/A"} />
                      <InfoCell label="Kurtosis" value={(ns.kurtosis as number)?.toFixed(4) ?? "N/A"} />
                      <InfoCell label="Skewness" value={(ns.skewness as number)?.toFixed(4) ?? "N/A"} />
                    </>
                  );
                })()}
                {(() => {
                  const cc = (report.forensics.noise as Record<string, unknown>)?.cross_channel as Record<string, unknown> | undefined;
                  if (!cc) return null;
                  return (
                    <>
                      <InfoCell label="Max Ch. Corr." value={(cc.max_correlation as number)?.toFixed(4) ?? "N/A"} />
                      <InfoCell label="Most Corr. Pair" value={(cc.most_correlated_pair as string) ?? "N/A"} />
                    </>
                  );
                })()}
              </div>
            </div>
          )}

          {/* Copy-Move */}
          {report.forensics.copy_move && Object.keys(report.forensics.copy_move).length > 0 && (
            <div>
              <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-2">Copy-Move Forgery Detection</h4>
              {(() => {
                const cm = report.forensics.copy_move as Record<string, unknown>;
                const total = cm.total_matches as number;
                return (
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                    <InfoCell label="DCT Matches" value={(cm.dct_matches as number)?.toString() ?? "0"} />
                    <InfoCell label="Keypoint Matches" value={(cm.keypoint_matches as number)?.toString() ?? "0"} />
                    <InfoCell label="Total Matches" value={total?.toString() ?? "0"} />
                  </div>
                );
              })()}
            </div>
          )}

          {/* CFA / Resampling */}
          {report.forensics.resampling && Object.keys(report.forensics.resampling).length > 0 && (
            <div>
              <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-2">CFA & Resampling Analysis</h4>
              {(() => {
                const rs = report.forensics.resampling as Record<string, unknown>;
                const cfa = rs.cfa as Record<string, unknown> | undefined;
                const resamp = rs.resampling as Record<string, unknown> | undefined;
                return (
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                    {cfa && (
                      <>
                        <InfoCell label="CFA Score" value={(cfa.cfa_score as number)?.toFixed(4) ?? "N/A"} />
                        <InfoCell label="Pattern" value={(cfa.dominant_pattern as string) ?? "N/A"} />
                      </>
                    )}
                    {resamp && (
                      <>
                        <StatusRow
                          label="Resampling"
                          value={(resamp.resampling_detected as boolean) ? "Detected" : "Not detected"}
                          positive={!(resamp.resampling_detected as boolean)}
                        />
                        {(resamp.resampling_detected as boolean) && (
                          <InfoCell label="Period" value={`${(resamp.period as number)?.toFixed(2) ?? "?"}px`} />
                        )}
                      </>
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          {(!report.forensics.ela || Object.keys(report.forensics.ela).length === 0) &&
           (!report.forensics.statistics || Object.keys(report.forensics.statistics).length === 0) &&
           (!report.forensics.noise || Object.keys(report.forensics.noise).length === 0) &&
           (!report.forensics.copy_move || Object.keys(report.forensics.copy_move).length === 0) &&
           (!report.forensics.resampling || Object.keys(report.forensics.resampling).length === 0) && (
            <p className="text-sm text-slate-500">No forensic analysis data available</p>
          )}
        </div>
      </Section>

      {/* Evidence Timeline */}
      <Section icon={Eye} title="Evidence Chain">
        <ProvenanceTimeline chain={report.evidence_chain} />
      </Section>

      {/* Metadata */}
      <Section icon={Hash} title="Metadata">
        <MetadataViewer metadata={report.provenance.metadata} />
      </Section>

      {/* Analyzer Details */}
      <Section icon={FileText} title="Analyzer Results">
        <div className="space-y-2">
          {analysis.evidence_results.map((er, i) => (
            <EvidenceCard key={i} result={er} />
          ))}
        </div>
      </Section>

      {/* Limitations */}
      {report.limitations.length > 0 && (
        <Section icon={AlertTriangle} title="Important Limitations">
          <div className="space-y-2">
            {report.limitations.map((lim, i) => (
              <div
                key={i}
                className="flex items-start gap-2 text-sm text-amber-400/80"
              >
                <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                {lim}
              </div>
            ))}
          </div>
        </Section>
      )}
    </div>
  );
}

function Section({
  icon: Icon,
  title,
  children,
}: {
  icon: typeof FileText;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-5">
      <div className="flex items-center gap-2 mb-4">
        <Icon className="w-4 h-4 text-slate-400" />
        <h3 className="text-sm font-medium text-slate-300 uppercase tracking-wider">
          {title}
        </h3>
      </div>
      {children}
    </div>
  );
}

function InfoCell({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className={`text-sm text-slate-200 mt-0.5 ${mono ? "font-mono" : ""}`}>
        {value}
      </dd>
    </div>
  );
}

function StatusRow({
  label,
  value,
  positive,
}: {
  label: string;
  value: string;
  positive?: boolean;
}) {
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="text-slate-500 w-24">{label}</span>
      <span
        className={
          positive === undefined
            ? "text-slate-300"
            : positive
              ? "text-green-400"
              : "text-red-400"
        }
      >
        {value}
      </span>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
