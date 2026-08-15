import axios from "axios";
import type {
  AnalysisSummary,
  AnalysisDetail,
  ForensicReport,
  HealthResponse,
} from "../types/analysis";

const api = axios.create({
  baseURL: "/api/v1",
  timeout: 120000,
});

export async function uploadImage(file: File): Promise<AnalysisSummary> {
  const formData = new FormData();
  formData.append("file", file);

  const response = await api.post<AnalysisSummary>("/analyze", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });

  return response.data;
}

export async function getAnalysis(id: string): Promise<AnalysisDetail> {
  const response = await api.get<AnalysisDetail>(`/analysis/${id}`);
  return response.data;
}

export async function getReport(id: string): Promise<ForensicReport> {
  const response = await api.get<ForensicReport>(`/analysis/${id}/report`);
  return response.data;
}

export async function getHealth(): Promise<HealthResponse> {
  const response = await api.get<HealthResponse>("/health");
  return response.data;
}

export async function pollAnalysis(
  id: string,
  onProgress?: (status: string) => void,
  maxAttempts = 60,
  intervalMs = 2000,
): Promise<AnalysisDetail> {
  for (let i = 0; i < maxAttempts; i++) {
    const analysis = await getAnalysis(id);
    onProgress?.(analysis.status);

    if (analysis.status === "completed" || analysis.status === "failed") {
      return analysis;
    }

    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }

  throw new Error("Analysis timed out");
}
