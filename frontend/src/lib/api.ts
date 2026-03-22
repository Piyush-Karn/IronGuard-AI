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

// --- Gateway Credentials for the Internal Dashboard ---
// In a real production app, these would be fetched once after login or set via env.
const SYSTEM_CLIENT_ID = "SYSTEM_DASHBOARD";
const SYSTEM_CLIENT_SECRET = "35_1fb20d6f4a8b7c2e_dashboard_secret";

async function generateGatewayHeaders(clientId: string, clientSecret: string, payload: string) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  
  // 1. Hash the body (payload) with SHA-256
  const encoder = new TextEncoder();
  const bodyData = encoder.encode(payload);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", bodyData);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const bodyHash = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

  // 2. Build canonical message: timestamp + \n + client_id + \n + body_hash
  const msg = `${timestamp}\n${clientId}\n${bodyHash}`;
  const msgData = encoder.encode(msg);
  const keyData = encoder.encode(clientSecret);

  // 3. HMAC-SHA256
  const key = await window.crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signatureBuffer = await window.crypto.subtle.sign(
    "HMAC",
    key,
    msgData
  );

  const signatureArray = Array.from(new Uint8Array(signatureBuffer));
  const signatureHex = signatureArray.map(b => b.toString(16).padStart(2, "0")).join("");

  return {
    "X-IG-Client-Id": clientId,
    "X-IG-Timestamp": timestamp,
    "X-IG-Signature": signatureHex,
  };
}

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
  // --- Secure Gateway AI Access ---
  scanPrompt: async (data: PromptRequest) => {
    const payload = JSON.stringify(data);
    const gatewayHeaders = await generateGatewayHeaders(SYSTEM_CLIENT_ID, SYSTEM_CLIENT_SECRET, payload);
    return request<ScanResponse>("/gateway/v1/scan", {
      method: "POST",
      body: payload,
      headers: gatewayHeaders,
    });
  },

  processPrompt: async (data: PromptRequest) => {
    const payload = JSON.stringify(data);
    const gatewayHeaders = await generateGatewayHeaders(SYSTEM_CLIENT_ID, SYSTEM_CLIENT_SECRET, payload);
    return request<ScanResponse>("/gateway/v1/process", {
      method: "POST",
      body: payload,
      headers: gatewayHeaders,
    });
  },

  // --- Auth & Verification ---
  verifySecret: (secret: string, userId: string) =>
    request<{ status: string, message: string }>("/api/v1/auth/verify-secret", {
        method: "POST",
        headers: { "X-User-Id": userId },
        body: JSON.stringify({ secret }),
    }),

  createUserInvite: (userId: string, adminId: string) =>
    request<any>(`/analytics/users/${userId}/invite`, {
        method: "POST",
        headers: { "X-User-Id": adminId },
    }),

  // --- Analytics & Admin ---
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
    
    return request<UserRoleResponse & { is_verified: boolean }>(`/auth/me${query}`, {
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

  unblockUser: (adminId: string, userId: string) => 
    request<{status: string, message: string}>("/unblock", {
      method: "POST",
      headers: { "X-User-Id": adminId, "Content-Type": "application/json" },
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
