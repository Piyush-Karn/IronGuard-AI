export interface RiskExplanation {
  risk_score: number;
  classification: string;
  reasons: string[];
  attack_types: string[];
}

export interface ScanResponse {
  risk_explanation: RiskExplanation;
  action: string;
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

const API_BASE_URL = "http://localhost:8000/api/v1";

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
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
    request<ScanResponse>("/scan_prompt", {
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
};
