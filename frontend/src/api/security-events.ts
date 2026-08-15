import type { SecurityEventsResponse } from "../types/security-events";

const RECENT_EVENTS_ENDPOINT = "/api/security-events/recent";

export class SecurityEventsApiError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = "SecurityEventsApiError";
  }
}

function isSecurityEventsResponse(value: unknown): value is SecurityEventsResponse {
  return (
    typeof value === "object" &&
    value !== null &&
    Array.isArray((value as { events?: unknown }).events)
  );
}

export async function fetchRecentSecurityEvents(
  limit = 50,
  signal?: AbortSignal,
): Promise<SecurityEventsResponse> {
  const response = await fetch(`${RECENT_EVENTS_ENDPOINT}?limit=${limit}`, {
    headers: { Accept: "application/json" },
    signal,
  });

  if (!response.ok) {
    const message =
      response.status === 503
        ? "The security-event service is temporarily unavailable."
        : `Unable to load security events (HTTP ${response.status}).`;
    throw new SecurityEventsApiError(message, response.status);
  }

  const payload: unknown = await response.json();
  if (!isSecurityEventsResponse(payload)) {
    throw new SecurityEventsApiError("The security-event service returned an invalid response.");
  }

  return payload;
}
