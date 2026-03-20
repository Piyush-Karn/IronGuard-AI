export interface RiskExplanation {
  risk_score: number;
  classification: string;
  reasons: string[];
  attack_types: string[];
}

export interface ScanResponse {
  risk_explanation: RiskExplanation;
  action: string;
  llm_response?: string;
  violation_notes?: any;
  sanitized_prompt?: string | null;
  sanitization_info?: {
    method: string;
    rules_applied: string[];
    intent_similarity: number;
  } | null;
  fingerprint_match?: boolean;
  fingerprint_method?: string | null;
}

export interface UserRoleResponse {
  user_id: string;
  role: "admin" | "employee";
}

export interface UserStatsResponse {
  total_checked: number;
  sanitized: number;
  blocked: number;
  trust_score: number;
  malicious_attempts: number;
}

export interface PromptRequest {
  user_id: string;
  user_email?: string;
  prompt: string;
  conversation_id?: string;
}

export interface AttackFrequencyData {
  labels: string[];
  datasets: {
    label: string;
    data: number[];
  }[];
}

export interface TopThreatsData {
  [key: string]: number;
}

export interface RiskDistributionData {
  [key: string]: number;
}

export interface UserListItem {
  user_id: string;
  role: string;
  trust_score: number;
  total_checked: number;
  sanitized: number;
  blocked: number;
  email: string;
  full_name: string;
}

export interface UserListResponse {
  users: UserListItem[];
}

export interface LatencyMetrics {
  avg_latency: number;
  max_latency: number;
  p95_latency: number;
}

export interface BlockingEfficiency {
  [key: string]: number;
}

export interface SanitizationRatio {
  ratio: number;
  sanitized: number;
  total: number;
}

export interface TopPolicyViolations {
  [key: string]: number;
}

export interface LogEntry {
  timestamp: string;
  user_id: string;
  user_email?: string;
  prompt: string;
  risk_score: number;
  classification: string;
  action_taken: string;
  ip_address?: string;
  reasons: string[];
  attack_types: string[];
  raw_detection_score: number;
}

export interface LogsResponse {
  logs: LogEntry[];
}

export interface GatewayClient {
  client_id: string;
  client_name: string;
  is_active: boolean;
  created_at: string;
  last_used: string | null;
  request_count: number;
  allowed_rpm: number;
  created_by: string;
}

export interface RegisterClientResponse {
  client_id: string;
  client_name: string;
  secret: string;
  warning: string;
}

export interface GatewayClientsResponse {
  clients: GatewayClient[];
}

const API_BASE_URL = "http://localhost:8000";

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  // If endpoint doesn't start with /api/v1 or /gateway/v1 or /gateway/admin, prefix with /api/v1
  let path = endpoint;
  if (!endpoint.startsWith("/api/v1") && !endpoint.startsWith("/gateway")) {
    path = `/api/v1${endpoint.startsWith("/") ? endpoint : `/${endpoint}`}`;
  }

  const url = `${API_BASE_URL}${path}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || "API request failed");
  }

  return response.json();
}

export const api = {
  scanPrompt: (data: PromptRequest) => 
    request<ScanResponse>("/api/v1/scan_prompt", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  processPrompt: (data: PromptRequest) =>
    request<ScanResponse>("/api/v1/process_prompt", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getAttackFrequency: (userId: string) => 
    request<AttackFrequencyData>("/analytics/attack-frequency", {
      headers: { "X-User-Id": userId }
    }),

  getTopThreats: (userId: string) => 
    request<TopThreatsData>("/analytics/top-threats", {
      headers: { "X-User-Id": userId }
    }),

  getRiskDistribution: (userId: string) => 
    request<RiskDistributionData>("/analytics/risk-distribution", {
      headers: { "X-User-Id": userId }
    }),

  getUserBehavior: (userId: string) => 
    request<any>("/analytics/user-behavior", {
      headers: { "X-User-Id": userId }
    }),

  getUserRole: (userId: string, email?: string, fullName?: string) => {
    const params = new URLSearchParams();
    if (email) params.append("email", email);
    if (fullName) params.append("full_name", fullName);
    const query = params.toString() ? `?${params.toString()}` : "";
    
    return request<UserRoleResponse>(`/auth/me${query}`, {
      headers: { "X-User-Id": userId },
    });
  },

  getUserStats: (userId: string) =>
    request<UserStatsResponse>("/users/me/stats", {
      headers: {
        "X-User-Id": userId,
      },
    }),

  getUsersList: (userId: string) =>
    request<UserListResponse>("/analytics/users", {
      headers: { "X-User-Id": userId }
    }),

  unblockUser: (userId: string) => 
    request<{status: string, message: string}>("/unblock", {
      method: "POST",
      body: JSON.stringify({ user_id: userId }),
    }),

  getLatencyMetrics: (userId: string) =>
    request<LatencyMetrics>("/analytics/metrics/latency-breakdown", {
      headers: { "X-User-Id": userId }
    }),

  getBlockingEfficiency: (userId: string) =>
    request<BlockingEfficiency>("/analytics/metrics/blocking-efficiency", {
      headers: { "X-User-Id": userId }
    }),

  getSanitizationRatio: (userId: string) =>
    request<SanitizationRatio>("/analytics/metrics/sanitization-ratio", {
      headers: { "X-User-Id": userId }
    }),

  pingAdmin: () => request<{ status: string, from: string }>("/analytics/ping"),

  getTopPolicyViolations: (adminId: string) => 
    request<Record<string, number>>("/analytics/metrics/top-policy-violations", { 
      headers: { "X-User-Id": adminId } 
    }),
  getLogs: (adminId: string) => request<{ logs: any[] }>("/analytics/logs", { headers: { "X-User-Id": adminId } }),
  getFingerprints: (adminId: string) => request<{ fingerprints: any[] }>("/analytics/fingerprints", { headers: { "X-User-Id": adminId } }),

  storeProviderKey: (adminId: string, provider: string, apiKey: string) =>
    request<{ message: string }>("/analytics/keys", {
      method: "POST",
      body: JSON.stringify({ provider, api_key: apiKey }),
      headers: { "X-User-Id": adminId, "Content-Type": "application/json" }
    }),

  listProviderKeys: (adminId: string) =>
    request<any[]>("/analytics/keys", { headers: { "X-User-Id": adminId } }),

  deleteProviderKey: (adminId: string, provider: string) =>
    request<{ message: string }>(`/analytics/keys/${provider}`, {
      method: "DELETE",
      headers: { "X-User-Id": adminId }
    }),

  // --- Gateway Client Management ---
  registerGatewayClient: (userId: string, data: { client_name: string, allowed_rpm?: number }) =>
    request<RegisterClientResponse>("/gateway/admin/clients", {
      method: "POST",
      headers: { "X-User-Id": userId },
      body: JSON.stringify(data),
    }),

  getGatewayClients: (userId: string) =>
    request<GatewayClientsResponse>("/gateway/admin/clients", {
      headers: { "X-User-Id": userId }
    }),

  rotateGatewaySecret: (userId: string, clientId: string) =>
    request<RegisterClientResponse>(`/gateway/admin/clients/${clientId}/rotate`, {
      method: "POST",
      headers: { "X-User-Id": userId }
    }),

  revokeGatewayClient: (userId: string, clientId: string, reason: string) =>
    request<{message: string}>(`/gateway/admin/clients/${clientId}`, {
      method: "DELETE",
      headers: { "X-User-Id": userId },
      body: JSON.stringify({ reason }),
    }),
};
