import { Loader2 } from "lucide-react";

interface Props {
  status: string;
}

const PHASE_LABELS: Record<string, string> = {
  pending: "Preparing analysis...",
  processing: "Running forensic analyzers...",
  completed: "Analysis complete",
  failed: "Analysis failed",
};

export default function AnalysisStatus({ status }: Props) {
  const label = PHASE_LABELS[status] ?? "Processing...";
  const isActive = status === "pending" || status === "processing";

  return (
    <div className="w-full max-w-md mx-auto text-center py-12">
      {isActive && (
        <Loader2 className="w-12 h-12 text-blue-500 animate-spin mx-auto mb-4" />
      )}
      <p className="text-lg font-medium text-slate-200">{label}</p>
      {isActive && (
        <div className="mt-6 space-y-2">
          <AnalysisStep label="File validation" active={true} />
          <AnalysisStep label="Hash generation" active={status === "processing"} />
          <AnalysisStep label="Format analysis" active={status === "processing"} />
          <AnalysisStep label="Metadata extraction" active={status === "processing"} />
          <AnalysisStep label="C2PA provenance check" active={status === "processing"} />
          <AnalysisStep label="Evidence fusion" active={status === "processing"} />
        </div>
      )}
    </div>
  );
}

function AnalysisStep({ label, active }: { label: string; active: boolean }) {
  return (
    <div className="flex items-center gap-3 text-sm">
      <div
        className={`w-2 h-2 rounded-full ${
          active ? "bg-blue-500 animate-pulse" : "bg-slate-600"
        }`}
      />
      <span className={active ? "text-slate-300" : "text-slate-500"}>
        {label}
      </span>
    </div>
  );
}
