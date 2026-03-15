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

  getAttackFrequency: () => 
    request<AttackFrequencyData>("/analytics/attack-frequency"),

  getTopThreats: () => 
    request<TopThreatsData>("/analytics/top-threats"),

  getRiskDistribution: () => 
    request<RiskDistributionData>("/analytics/risk-distribution"),

  getUserBehavior: () => 
    request<any>("/analytics/user-behavior"),
};
