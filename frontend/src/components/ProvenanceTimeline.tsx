import type { EvidenceItem } from "../types/analysis";
import { ArrowDown, Camera, Cpu, Paintbrush, FileOutput, HelpCircle } from "lucide-react";

interface Props {
  chain: EvidenceItem[];
}

const CATEGORY_ICONS: Record<string, typeof Camera> = {
  camera_signature: Camera,
  software_signature: Paintbrush,
  provenance: Cpu,
  compression: FileOutput,
};

const SUPPORTS_COLORS: Record<string, string> = {
  verified_ai_provenance: "border-red-500/50 bg-red-500/10",
  likely_ai_generated: "border-orange-500/50 bg-orange-500/10",
  likely_original: "border-green-500/50 bg-green-500/10",
  conventionally_edited: "border-blue-500/50 bg-blue-500/10",
  has_provenance: "border-purple-500/50 bg-purple-500/10",
};

export default function ProvenanceTimeline({ chain }: Props) {
  if (chain.length === 0) {
    return (
      <div className="text-sm text-slate-500 italic">
        No evidence chain reconstructed
      </div>
    );
  }

  return (
    <div className="space-y-1">
      {chain.map((item, i) => {
        const Icon = CATEGORY_ICONS[item.category] ?? HelpCircle;
        const color = SUPPORTS_COLORS[item.supports ?? ""] ?? "border-slate-600 bg-slate-800/30";

        return (
          <div key={i}>
            {i > 0 && (
              <div className="flex justify-center py-0.5">
                <ArrowDown className="w-4 h-4 text-slate-600" />
              </div>
            )}
            <div
              className={`flex items-start gap-3 px-4 py-3 rounded-lg border ${color}`}
            >
              <Icon className="w-5 h-5 text-slate-400 mt-0.5 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-sm text-slate-200">{item.description}</p>
                <div className="flex items-center gap-3 mt-1">
                  <span className="text-xs text-slate-500">
                    Source: {item.source}
                  </span>
                  {item.confidence !== null && (
                    <span className="text-xs font-mono text-slate-500">
                      Confidence: {Math.round(item.confidence * 100)}%
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
