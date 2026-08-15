import { useState } from "react";
import ImageUpload from "../components/ImageUpload";
import AnalysisStatus from "../components/AnalysisStatus";
import ForensicReportView from "../components/ForensicReport";
import { uploadImage, getAnalysis, getReport } from "../services/api";
import type { AnalysisDetail, ForensicReport } from "../types/analysis";
import { AlertCircle, RotateCcw } from "lucide-react";

type AppState = "upload" | "processing" | "results" | "error";

export default function AnalyzePage() {
  const [state, setState] = useState<AppState>("upload");
  const [status, setStatus] = useState("pending");
  const [analysis, setAnalysis] = useState<AnalysisDetail | null>(null);
  const [report, setReport] = useState<ForensicReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleUpload = async (file: File) => {
    setState("processing");
    setStatus("pending");
    setError(null);

    try {
      const summary = await uploadImage(file);
      setStatus(summary.status);

      if (summary.status === "failed") {
        setState("error");
        setError("Analysis failed during processing");
        return;
      }

      const detail = await getAnalysis(summary.analysis_id);
      setAnalysis(detail);

      if (detail.status === "failed") {
        setState("error");
        setError(detail.error_message ?? "Analysis failed");
        return;
      }

      const reportData = await getReport(summary.analysis_id);
      setReport(reportData);
      setState("results");
    } catch (err) {
      setState("error");
      setError(err instanceof Error ? err.message : "An error occurred");
    }
  };

  const handleReset = () => {
    setState("upload");
    setAnalysis(null);
    setReport(null);
    setError(null);
  };

  return (
    <div className="min-h-screen bg-slate-950">
      <header className="border-b border-slate-800 bg-slate-900/50">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center">
              <svg
                className="w-5 h-5 text-white"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
            </div>
            <div>
              <h1 className="text-lg font-semibold text-slate-100">
                Image Provenance System
              </h1>
              <p className="text-xs text-slate-500">
                Digital forensic analysis
              </p>
            </div>
          </div>

          {state !== "upload" && (
            <button
              onClick={handleReset}
              className="flex items-center gap-2 px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              New Analysis
            </button>
          )}
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-8">
        {state === "upload" && (
          <div className="py-12">
            <div className="text-center mb-8">
              <h2 className="text-2xl font-semibold text-slate-100 mb-2">
                Analyze Image Provenance
              </h2>
              <p className="text-slate-400 max-w-lg mx-auto">
                Upload an image for comprehensive forensic analysis including
                metadata extraction, C2PA provenance verification, format
                analysis, and evidence fusion.
              </p>
            </div>
            <ImageUpload onUpload={handleUpload} isLoading={false} />
          </div>
        )}

        {state === "processing" && <AnalysisStatus status={status} />}

        {state === "error" && (
          <div className="max-w-md mx-auto py-12 text-center">
            <AlertCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />
            <p className="text-lg font-medium text-slate-200 mb-2">
              Analysis Failed
            </p>
            <p className="text-sm text-slate-400 mb-6">{error}</p>
            <button
              onClick={handleReset}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            >
              Try Again
            </button>
          </div>
        )}

        {state === "results" && analysis && report && (
          <ForensicReportView analysis={analysis} report={report} />
        )}
      </main>

      <footer className="border-t border-slate-800 mt-12 py-4">
        <div className="max-w-6xl mx-auto px-4 text-center text-xs text-slate-600">
          Image Provenance System v0.1.0 — Phase 1: Evidence Foundation
        </div>
      </footer>
    </div>
  );
}
