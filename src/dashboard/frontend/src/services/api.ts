import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

export interface ProjectInfo {
  project_name: string;
  target_url: string;
  program_name: string;
  description: string;
  created_at: string;
  last_scan_at: string;
  tags: string[];
  total_findings: number;
}

export interface Finding {
  id: string;
  vuln_type: string;
  severity: string;
  title: string;
  description: string;
  target_url: string;
  discovered_at: string;
  source_agent: string;
  confidence: number;
  cwe_id?: string;
  cvss_score?: number;
}

export interface VulnerabilityScore {
  total_score: number;
  cvss_avg: number;
  findings_count: number;
  severity_breakdown: Record<string, number>;
  recommendations: string[];
}

export interface PerformanceData {
  total_duration: number;
  estimated_cost: number;
  tasks_per_minute: number;
  success_rate: number;
  total_tasks: number;
  successful_tasks: number;
  failed_tasks: number;
}

export interface SessionMetrics {
  project_name: string;
  session_id: string;
  start_time: string;
  end_time?: string;
  performance: PerformanceData;
  phase_breakdown: Record<string, number>;
  token_usage: Record<string, any>;
  skip_reason_counts: Record<string, number>;
  skip_reason_unknown_counts: Record<string, number>;
  low_ssrf_score_breakdown: Record<string, number>;
  skip_reason_other_ratio: number;
  low_ssrf_top_missing_feature: string;
  skip_reason_unknown_alert: {
    triggered: boolean;
    unknown_count: number;
    total_skip_count: number;
    unknown_ratio: number;
    threshold_count: number;
    threshold_ratio: number;
  };
  skip_reason_timeline: Array<{
    task_index: number;
    task_id: string;
    task_name: string;
    delta: Record<string, number>;
    cumulative: Record<string, number>;
  }>;
}

export const projectsApi = {
  list: () => api.get<ProjectInfo[]>("/api/projects"),

  getFindings: (
    projectName: string,
    params?: {
      severity?: string;
      vuln_type?: string;
      min_confidence?: number;
    },
  ) => api.get<Finding[]>(`/api/projects/${projectName}/findings`, { params }),

  getScore: (projectName: string) =>
    api.get<VulnerabilityScore>(`/api/projects/${projectName}/score`),

  getMetrics: (projectName: string) =>
    api.get<SessionMetrics>(`/api/projects/${projectName}/metrics`),
};

export default api;
