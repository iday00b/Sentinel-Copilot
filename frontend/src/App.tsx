import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import {
  fetchRecentSecurityEvents,
  SecurityEventsApiError,
} from "./api/security-events";
import type { EventField, SecurityEvent } from "./types/security-events";

type RequestState = "loading" | "refreshing" | "ready" | "error";
type IconName = "activity" | "alert" | "host" | "shield";

const RECENT_EVENT_LIMIT = 50;

function Icon({ name }: { name: IconName }) {
  const paths: Record<IconName, ReactNode> = {
    activity: <path d="M3 12h4l2.5-7 5 14 2.5-7h4" />,
    alert: (
      <>
        <path d="M12 9v4" />
        <path d="M12 17h.01" />
        <path d="m10.3 3.5-8 14A2 2 0 0 0 4 20.5h16a2 2 0 0 0 1.7-3l-8-14a2 2 0 0 0-3.4 0Z" />
      </>
    ),
    host: (
      <>
        <rect width="18" height="14" x="3" y="3" rx="2" />
        <path d="M7 21h10M12 17v4" />
      </>
    ),
    shield: <path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V5l8-3 8 3v8Z" />,
  };

  return (
    <svg aria-hidden="true" viewBox="0 0 24 24">
      {paths[name]}
    </svg>
  );
}

function fieldValues(value?: EventField): string[] {
  if (Array.isArray(value)) {
    return value.filter((item) => typeof item === "string" && item.trim().length > 0);
  }
  return typeof value === "string" && value.trim().length > 0 ? [value] : [];
}

function displayField(value?: EventField, fallback = "—"): string {
  const values = fieldValues(value);
  return values.length > 0 ? values.join(", ") : fallback;
}

function firstValue(...values: Array<string | undefined>): string | undefined {
  return values.find((value) => typeof value === "string" && value.trim().length > 0);
}

function eventSeverity(event: SecurityEvent): number | undefined {
  const severity = event.event?.severity;
  return typeof severity === "number" && Number.isFinite(severity) ? severity : undefined;
}

function severityTone(severity?: number): string {
  if (severity === undefined) return "neutral";
  if (severity >= 9) return "critical";
  if (severity >= 7) return "high";
  if (severity >= 4) return "medium";
  return "low";
}

function outcomeTone(outcome?: string): string {
  const normalized = outcome?.toLowerCase();
  if (normalized === "failure") return "failure";
  if (normalized === "success") return "success";
  return "neutral";
}

function formatTimestamp(timestamp?: string): { date: string; time: string } {
  if (!timestamp) return { date: "Unknown date", time: "—" };
  const value = new Date(timestamp);
  if (Number.isNaN(value.getTime())) return { date: "Unknown date", time: "—" };

  return {
    date: new Intl.DateTimeFormat(undefined, {
      month: "short",
      day: "2-digit",
      year: "numeric",
    }).format(value),
    time: new Intl.DateTimeFormat(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).format(value),
  };
}

function formatRefreshTime(value?: Date): string {
  if (!value) return "Waiting for first sync";
  return `Updated ${new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(value)}`;
}

function App() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [requestState, setRequestState] = useState<RequestState>("loading");
  const [errorMessage, setErrorMessage] = useState<string>();
  const [lastUpdated, setLastUpdated] = useState<Date>();
  const activeRequest = useRef<AbortController>();

  const loadEvents = useCallback(async (initial = false) => {
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    setRequestState(initial ? "loading" : "refreshing");
    setErrorMessage(undefined);

    try {
      const response = await fetchRecentSecurityEvents(RECENT_EVENT_LIMIT, controller.signal);
      setEvents(response.events);
      setLastUpdated(new Date());
      setRequestState("ready");
    } catch (error) {
      if (controller.signal.aborted) return;
      setErrorMessage(
        error instanceof SecurityEventsApiError
          ? error.message
          : "Unable to reach the security-event service.",
      );
      setRequestState("error");
    } finally {
      if (activeRequest.current === controller) activeRequest.current = undefined;
    }
  }, []);

  useEffect(() => {
    void loadEvents(true);
    return () => activeRequest.current?.abort();
  }, [loadEvents]);

  const metrics = useMemo(() => {
    const uniqueHosts = new Set<string>();
    let failures = 0;
    let highSeverity = 0;

    for (const event of events) {
      if (event.event?.outcome?.toLowerCase() === "failure") failures += 1;
      if ((eventSeverity(event) ?? 0) >= 7) highSeverity += 1;
      const host = firstValue(event.host?.name, event.host?.hostname, ...fieldValues(event.host?.ip));
      if (host) uniqueHosts.add(host);
    }

    return [
      { label: "Events in view", value: events.length, icon: "activity" as const, tone: "cyan" },
      { label: "Failed outcomes", value: failures, icon: "alert" as const, tone: "red" },
      { label: "High severity", value: highSeverity, icon: "shield" as const, tone: "amber" },
      { label: "Unique hosts", value: uniqueHosts.size, icon: "host" as const, tone: "violet" },
    ];
  }, [events]);

  const isWorking = requestState === "loading" || requestState === "refreshing";
  const hasEvents = events.length > 0;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark"><Icon name="shield" /></span>
          <span><strong>Sentinel</strong><small>Copilot</small></span>
        </div>
        <nav aria-label="Primary navigation">
          <p className="nav-label">Workspace</p>
          <span className="nav-item active"><Icon name="activity" />Overview</span>
          <span className="nav-item"><Icon name="alert" />Event stream</span>
          <p className="nav-label">Operations</p>
          <span className="nav-item muted"><Icon name="shield" />Investigations<small>Soon</small></span>
        </nav>
        <div className="sidebar-status">
          <span className={`status-dot ${requestState === "error" ? "offline" : ""}`} />
          <span><strong>Data pipeline</strong><small>{requestState === "error" ? "Attention required" : "Operational"}</small></span>
        </div>
      </aside>

      <main className="dashboard">
        <header className="topbar">
          <div>
            <p className="eyebrow">Security operations</p>
            <h1>SOC overview</h1>
            <p className="subtitle">Live visibility into normalized security events across your environment.</p>
          </div>
          <div className="topbar-actions">
            <span className={`connection-state ${requestState === "error" ? "degraded" : ""}`}>
              <span className="status-dot" />
              {requestState === "error" ? "Service degraded" : "Pipeline connected"}
            </span>
            <button className="refresh-button" onClick={() => void loadEvents()} disabled={isWorking}>
              <svg className={isWorking ? "spinning" : ""} aria-hidden="true" viewBox="0 0 24 24">
                <path d="M20 11a8.1 8.1 0 0 0-15.5-2M4 4v5h5M4 13a8.1 8.1 0 0 0 15.5 2m.5 5v-5h-5" />
              </svg>
              {requestState === "refreshing" ? "Refreshing" : "Refresh"}
            </button>
          </div>
        </header>

        <section className="metrics-grid" aria-label="Event summary">
          {metrics.map((metric) => (
            <article className={`metric-card ${metric.tone}`} key={metric.label}>
              <span className="metric-icon"><Icon name={metric.icon} /></span>
              <div><p>{metric.label}</p><strong>{requestState === "loading" ? "—" : metric.value}</strong></div>
              <span className="metric-caption">Last {RECENT_EVENT_LIMIT} events</span>
            </article>
          ))}
        </section>

        {errorMessage && hasEvents && (
          <div className="inline-alert" role="alert">
            <Icon name="alert" />
            <span><strong>Refresh failed</strong>{errorMessage} Showing the last successful result.</span>
          </div>
        )}

        <section className="events-panel" aria-labelledby="recent-events-title">
          <div className="panel-header">
            <div>
              <h2 id="recent-events-title">Recent security events</h2>
              <p>Newest normalized events from the detection pipeline</p>
            </div>
            <span className="last-updated">{formatRefreshTime(lastUpdated)}</span>
          </div>

          {requestState === "loading" && (
            <div className="state-view" role="status">
              <span className="loader" />
              <h3>Loading security events</h3>
              <p>Connecting to the event pipeline…</p>
            </div>
          )}

          {requestState === "error" && !hasEvents && (
            <div className="state-view error-state" role="alert">
              <span className="state-icon"><Icon name="alert" /></span>
              <h3>Events could not be loaded</h3>
              <p>{errorMessage}</p>
              <button className="secondary-button" onClick={() => void loadEvents()}>Try again</button>
            </div>
          )}

          {requestState === "ready" && !hasEvents && (
            <div className="state-view">
              <span className="state-icon"><Icon name="shield" /></span>
              <h3>No security events yet</h3>
              <p>Events will appear here after they are ingested and normalized.</p>
            </div>
          )}

          {hasEvents && (
            <div className={`table-wrap ${requestState === "refreshing" ? "is-refreshing" : ""}`}>
              <table>
                <thead><tr><th>Time</th><th>Severity</th><th>Event</th><th>Host</th><th>Source</th><th>User</th><th>Outcome</th></tr></thead>
                <tbody>
                  {events.map((event, index) => {
                    const timestamp = formatTimestamp(event["@timestamp"]);
                    const severity = eventSeverity(event);
                    const outcome = firstValue(event.event?.outcome) ?? "Unknown";
                    const title = firstValue(event.rule?.name, event.message, event.event?.action) ?? "Unclassified event";
                    const host = firstValue(event.host?.name, event.host?.hostname, ...fieldValues(event.host?.ip)) ?? "Unknown host";
                    const sourceIp = displayField(event.source?.ip, "Unknown source");
                    const source = event.source?.port ? `${sourceIp}:${event.source.port}` : sourceIp;
                    const username = firstValue(event.user?.name, ...fieldValues(event.related?.user)) ?? "Unknown user";
                    const domain = firstValue(event.user?.domain);
                    const rowKey = `${event["@timestamp"] ?? "event"}-${event.rule?.id ?? event.event?.action ?? index}-${index}`;

                    return (
                      <tr key={rowKey}>
                        <td><span className="time-primary">{timestamp.time}</span><span className="cell-secondary">{timestamp.date}</span></td>
                        <td><span className={`badge severity ${severityTone(severity)}`}><span />{severity ?? "N/A"}</span></td>
                        <td className="event-cell"><span className="event-title">{title}</span><span className="cell-secondary">{event.rule?.name && event.message ? event.message : firstValue(event.event?.dataset, event.event?.provider, displayField(event.event?.category))}</span></td>
                        <td><span className="cell-primary">{host}</span><span className="cell-secondary">{displayField(event.host?.ip, displayField(event.related?.ip))}</span></td>
                        <td><span className="mono-value">{source}</span></td>
                        <td><span className="cell-primary">{domain ? `${domain}\\${username}` : username}</span><span className="cell-secondary">{event.user?.id}</span></td>
                        <td><span className={`badge outcome ${outcomeTone(outcome)}`}>{outcome}</span></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
