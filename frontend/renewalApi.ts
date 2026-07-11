/**
 * Typed client for the CertRenewal.Api endpoints. Wire the panel like:
 *
 *   const api = createRenewalApi({ tenantId });
 *   <CertificateRenewalPanel
 *     certificate={cert}
 *     renewalState={state}
 *     onEnable={(days) => api.enable(cert.id, { renewalWindowDays: days })}
 *     onDisable={() => api.disable(cert.id)}
 *     onUpdateWindow={(days) => api.patch(cert.id, { renewalWindowDays: days })}
 *     onUpdateMode={(mode) => api.patch(cert.id, { renewalMode: mode })}
 *     onTriggerNow={() => api.trigger(cert.id)}
 *   />
 *
 * Refetch getState() after each mutation resolves.
 *
 * INTEGRATION POINT: `getHeaders` must supply your real auth headers; the
 * X-User-Email default matches the dev-only HeaderActorResolver and must be
 * replaced together with it.
 */

import type {
  RenewalAttemptInfo,
  RenewalMode,
  RenewalState,
} from "./CertificateRenewalPanel";

export interface RenewalApiConfig {
  tenantId: string;
  /** Defaults to NEXT_PUBLIC_CLEAR_OPS_API_BASE_URL, e.g. "https://api.clearcloudai.com/api/v1". */
  baseUrl?: string;
  /** Supply auth headers per request (dev default: none). */
  getHeaders?: () => Record<string, string> | Promise<Record<string, string>>;
}

export interface EnableBody {
  renewalWindowDays?: number;
  renewalMode?: RenewalMode;
}

export interface PatchBody {
  renewalWindowDays?: number;
  renewalMode?: RenewalMode;
  dryRunOverride?: boolean | null;
  maxAttempts?: number;
  retryIntervalMinutes?: number;
}

export interface ApprovalInfo {
  id: string;
  certificateId: string;
  expirationWindowKey: string;
  status: "pending" | "approved" | "rejected";
  requestedBy: string;
  requestedAt: string;
  approvedBy?: string | null;
  approvedAt?: string | null;
  rejectedBy?: string | null;
  rejectedAt?: string | null;
  notes?: string | null;
}

export function createRenewalApi(config: RenewalApiConfig) {
  const base =
    config.baseUrl ?? process.env.NEXT_PUBLIC_CLEAR_OPS_API_BASE_URL ?? "/api/v1";
  const tenant = encodeURIComponent(config.tenantId);

  async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = {
      "Content-Type": "application/json",
      ...(config.getHeaders ? await config.getHeaders() : {}),
      ...(init.headers as Record<string, string> | undefined),
    };
    const response = await fetch(`${base}${path}`, { ...init, headers });
    if (!response.ok) {
      let detail = response.statusText;
      try {
        const body = (await response.json()) as { detail?: string };
        if (body.detail) detail = body.detail;
      } catch {
        /* non-JSON error body */
      }
      throw new Error(detail);
    }
    return (await response.json()) as T;
  }

  const certPath = (certId: string) =>
    `/tenants/${tenant}/certificates/${encodeURIComponent(certId)}/renewal`;

  return {
    getState: (certId: string) => request<RenewalState>(certPath(certId)),

    enable: (certId: string, body: EnableBody = {}) =>
      request<RenewalState["policy"]>(`${certPath(certId)}/enable`, {
        method: "PUT",
        body: JSON.stringify(body),
      }),

    disable: (certId: string) =>
      request<RenewalState["policy"]>(`${certPath(certId)}/disable`, {
        method: "PUT",
      }),

    patch: (certId: string, body: PatchBody) =>
      request<RenewalState["policy"]>(certPath(certId), {
        method: "PATCH",
        body: JSON.stringify(body),
      }),

    listAttempts: (certId: string, limit = 50) =>
      request<RenewalAttemptInfo[]>(`${certPath(certId)}/attempts?limit=${limit}`),

    /** 202 (awaiting approval) resolves with the pending-approval payload. */
    trigger: (certId: string) =>
      request<RenewalAttemptInfo | { detail: string; approval: ApprovalInfo | null }>(
        `${certPath(certId)}/trigger`,
        { method: "POST" }
      ),

    listPendingApprovals: () =>
      request<ApprovalInfo[]>(`/tenants/${tenant}/renewal-approvals`),

    approve: (approvalId: string, notes?: string) =>
      request<RenewalAttemptInfo>(
        `/tenants/${tenant}/renewal-approvals/${encodeURIComponent(approvalId)}/approve`,
        { method: "POST", body: JSON.stringify({ notes: notes ?? null }) }
      ),

    reject: (approvalId: string, notes?: string) =>
      request<ApprovalInfo>(
        `/tenants/${tenant}/renewal-approvals/${encodeURIComponent(approvalId)}/reject`,
        { method: "POST", body: JSON.stringify({ notes: notes ?? null }) }
      ),
  };
}

export type RenewalApi = ReturnType<typeof createRenewalApi>;
