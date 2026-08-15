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

      {/* ML Status */}
      <Section icon={Cpu} title="AI Detection (ML)">
        {report.ml.status === "not_implemented" ? (
          <p className="text-sm text-amber-400/70">
            ML-based AI detection is not yet implemented.
            Classification is based on metadata and provenance signals only.
          </p>
        ) : (
          <div className="grid grid-cols-3 gap-4">
            <ConfidenceIndicator value={report.ml.ai_generated} label="AI Generated" />
            <ConfidenceIndicator value={report.ml.ai_edited} label="AI Edited" />
            <ConfidenceIndicator value={report.ml.conventional_edit} label="Conv. Edit" />
          </div>
        )}
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
