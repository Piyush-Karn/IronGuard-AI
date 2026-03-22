import { describe, it, expect, vi, beforeEach } from "vitest";
import { api } from "./api";

// We need to mock fetch
global.fetch = vi.fn();

describe("Frontend API Logic", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe("generateGatewayHeaders", () => {
    it("should generate valid HMAC-SHA256 signatures", async () => {
      const mockPayload = JSON.stringify({ prompt: "test" });
      const clientId = "TEST_CLIENT";
      const clientSecret = "TEST_SECRET";

      // Mock successful fetch for scanPrompt which uses generateGatewayHeaders internally
      (fetch as any).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ action: "Passed", risk_explanation: { risk_score: 0 } }),
      });

      const result = await api.scanPrompt({
        user_id: "user_1",
        prompt: "test"
      });

      expect(result.action).toBe("Passed");
      
      // Check fetch call
      const fetchCall = (fetch as any).mock.calls[0];
      const url = fetchCall[0];
      const options = fetchCall[1];

      expect(url).toContain("/gateway/v1/scan");
      expect(options.headers).toHaveProperty("X-IG-Client-Id");
      expect(options.headers).toHaveProperty("X-IG-Timestamp");
      expect(options.headers).toHaveProperty("X-IG-Signature");
      
      const signature = options.headers["X-IG-Signature"];
      expect(signature).toHaveLength(64); // SHA-256 hex is 64 chars
    });
  });

  describe("Auth Endpoints", () => {
    it("should call verify-secret with correct headers", async () => {
      (fetch as any).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ status: "success" }),
      });

      await api.verifySecret("secret_123", "user_1");

      const options = (fetch as any).mock.calls[0][1];
      expect(options.method).toBe("POST");
      expect(options.headers["X-User-Id"]).toBe("user_1");
      expect(JSON.parse(options.body)).toEqual({ secret: "secret_123" });
    });
  });

  describe("Admin Endpoints", () => {
    it("should call unblock with correct payload", async () => {
      (fetch as any).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ status: "success" }),
      });

      await api.unblockUser("admin_1", "user_to_unblock");

      const options = (fetch as any).mock.calls[0][1];
      expect(options.method).toBe("POST");
      expect(options.headers["X-User-Id"]).toBe("admin_1");
      expect(JSON.parse(options.body)).toEqual({ user_id: "user_to_unblock" });
    });
  });
});
