import type {
  AlertAction,
  AlertSummary,
  AlertsResponse,
  AlertStatus,
  SecurityAlert,
} from "../types/alerts";

const ALERTS_ENDPOINT = "/api/alerts";

export class AlertsApiError extends Error {
  constructor(message: string, public readonly status?: number) {
    super(message);
    this.name = "AlertsApiError";
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    headers: { Accept: "application/json", ...options?.headers },
    ...options,
  });
  if (!response.ok) {
    throw new AlertsApiError(`Alert service request failed (HTTP ${response.status}).`, response.status);
  }
  return response.json() as Promise<T>;
}

export function fetchAlertSummary(signal?: AbortSignal): Promise<AlertSummary> {
  return request<AlertSummary>(`${ALERTS_ENDPOINT}/summary`, { signal });
}

export function fetchAlerts(
  options: { status?: AlertStatus | "all"; limit?: number; signal?: AbortSignal } = {},
): Promise<AlertsResponse> {
  const params = new URLSearchParams({ limit: String(options.limit ?? 50) });
  if (options.status && options.status !== "all") params.set("status", options.status);
  return request<AlertsResponse>(`${ALERTS_ENDPOINT}?${params}`, { signal: options.signal });
}

export function updateAlert(
  alertId: string,
  action: AlertAction,
  signal?: AbortSignal,
): Promise<SecurityAlert> {
  return request<SecurityAlert>(`${ALERTS_ENDPOINT}/${encodeURIComponent(alertId)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, actor: "analyst" }),
    signal,
  });
}
