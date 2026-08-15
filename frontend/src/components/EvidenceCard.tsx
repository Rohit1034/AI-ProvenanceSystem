import type { EvidenceResultData } from "../types/analysis";
import ConfidenceIndicator from "./ConfidenceIndicator";
import {
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { useState } from "react";

interface Props {
  result: EvidenceResultData;
}

const STATUS_ICONS: Record<string, typeof CheckCircle> = {
  completed: CheckCircle,
  error: XCircle,
  not_implemented: AlertTriangle,
  pending: Clock,
};

const STATUS_COLORS: Record<string, string> = {
  completed: "text-green-400",
  error: "text-red-400",
  not_implemented: "text-amber-400",
  pending: "text-slate-400",
};

export default function EvidenceCard({ result }: Props) {
  const [expanded, setExpanded] = useState(false);
  const Icon = STATUS_ICONS[result.status] ?? AlertTriangle;
  const color = STATUS_COLORS[result.status] ?? "text-slate-400";

  return (
    <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 flex items-center gap-3 hover:bg-slate-700/30 transition-colors"
      >
        <Icon className={`w-5 h-5 flex-shrink-0 ${color}`} />
        <div className="flex-1 text-left">
          <span className="text-sm font-medium text-slate-200">
            {formatAnalyzerName(result.analyzer_name)}
          </span>
          <span className="text-xs text-slate-500 ml-2">
            v{result.analyzer_version}
          </span>
        </div>
        {result.duration_ms !== null && (
          <span className="text-xs text-slate-500 font-mono">
            {result.duration_ms}ms
          </span>
        )}
        {expanded ? (
          <ChevronDown className="w-4 h-4 text-slate-500" />
        ) : (
          <ChevronRight className="w-4 h-4 text-slate-500" />
        )}
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-slate-700/50 pt-3">
          {result.confidence !== null && (
            <ConfidenceIndicator value={result.confidence} />
          )}

          {result.findings && result.findings.length > 0 && (
            <div>
              <h4 className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                Findings
              </h4>
              <div className="space-y-1.5">
                {result.findings.map((finding, i) => (
                  <div
                    key={i}
                    className="text-xs font-mono bg-slate-900/50 rounded px-3 py-2 text-slate-300"
                  >
                    {formatFinding(finding)}
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.limitations && result.limitations.length > 0 && (
            <div>
              <h4 className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                Limitations
              </h4>
              {result.limitations.map((lim, i) => (
                <p key={i} className="text-xs text-amber-400/70 mb-1">
                  {lim}
                </p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function formatAnalyzerName(name: string): string {
  return name.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatFinding(finding: Record<string, unknown>): string {
  const type = finding["type"] as string | undefined;
  const desc = finding["description"] as string | undefined;

  if (desc) return desc;

  const parts: string[] = [];
  if (type) parts.push(`[${type}]`);

  for (const [k, v] of Object.entries(finding)) {
    if (k === "type") continue;
    parts.push(`${k}: ${String(v)}`);
  }

  return parts.join(" | ");
}
