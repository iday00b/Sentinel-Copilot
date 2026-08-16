import { useCallback, useEffect, useMemo, useState } from "react";

import {
  AlertsApiError,
  fetchAlerts,
  fetchAlertSummary,
  updateAlert,
} from "../api/alerts";
import type { AlertAction, AlertStatus, AlertSummary, SecurityAlert } from "../types/alerts";

interface AlertsWorkspaceProps {
  onSummaryChange: (summary: AlertSummary) => void;
}

function severityTone(severity: number): "critical" | "high" | "medium" | "low" {
  if (severity >= 9) return "critical";
  if (severity >= 7) return "high";
  if (severity >= 4) return "medium";
  return "low";
}

function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return "Unknown time";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function statusLabel(status: AlertStatus): string {
  return status === "acknowledged" ? "Acknowledged" : status[0].toUpperCase() + status.slice(1);
}

export default function AlertsWorkspace({ onSummaryChange }: AlertsWorkspaceProps) {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [summary, setSummary] = useState<AlertSummary>();
  const [statusFilter, setStatusFilter] = useState<AlertStatus | "all">("open");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [updatingId, setUpdatingId] = useState<string>();

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError(undefined);
    try {
      const [alertsResponse, summaryResponse] = await Promise.all([
        fetchAlerts({ status: statusFilter, signal }),
        fetchAlertSummary(signal),
      ]);
      setAlerts(alertsResponse.alerts);
      setSummary(summaryResponse);
      onSummaryChange(summaryResponse);
    } catch (reason) {
      if (signal?.aborted) return;
      setError(reason instanceof AlertsApiError ? reason.message : "Unable to load alert data.");
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, [onSummaryChange, statusFilter]);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const cards = useMemo(() => [
    { label: "Open", value: summary?.open ?? 0, tone: "blue" },
    { label: "Critical", value: summary?.critical ?? 0, tone: "critical" },
    { label: "High", value: summary?.high ?? 0, tone: "high" },
    { label: "Escalated", value: summary?.escalated ?? 0, tone: "violet" },
  ], [summary]);

  async function applyAction(alert: SecurityAlert, action: AlertAction) {
    setUpdatingId(alert.alert_id);
    try {
      const updated = await updateAlert(alert.alert_id, action);
      setAlerts((current) => current.map((item) => item.alert_id === updated.alert_id ? updated : item));
      await load();
    } catch (reason) {
      setError(reason instanceof AlertsApiError ? reason.message : "Unable to update the alert.");
    } finally {
      setUpdatingId(undefined);
    }
  }

  return (
    <div className="workspace alerts-workspace">
      <header className="alerts-workspace-header">
        <div><p>Detection engine</p><h2>Alert queue</h2><span>Rule-generated alerts with persistent analyst lifecycle state.</span></div>
        <button onClick={() => void load()} disabled={loading}>↻ Refresh alerts</button>
      </header>

      <section className="alert-summary-grid" aria-label="Alert summary">
        {cards.map((card) => <article className={`alert-summary-card ${card.tone}`} key={card.label}><span>{card.label}</span><strong>{loading ? "—" : card.value}</strong><small>Detection engine</small></article>)}
      </section>

      <section className="alert-queue-panel">
        <div className="alert-queue-toolbar"><div><h3>Alerts</h3><span>{summary?.total ?? 0} total</span></div><label>Status<select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as AlertStatus | "all")}><option value="all">All statuses</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="escalated">Escalated</option><option value="dismissed">Dismissed</option></select></label></div>
        {error && <div className="alerts-error" role="alert">{error}<button onClick={() => void load()}>Retry</button></div>}
        {loading && <div className="alerts-loading" role="status">Loading rule-generated alerts…</div>}
        {!loading && !error && alerts.length === 0 && <div className="alerts-empty"><strong>No {statusFilter === "all" ? "" : statusFilter} alerts</strong><span>New alerts will appear here when enabled detection rules match incoming security events.</span></div>}
        {!loading && alerts.length > 0 && <div className="alerts-table-wrap"><table className="alerts-table"><thead><tr><th>Severity</th><th>Alert</th><th>Rule</th><th>Entities</th><th>MITRE</th><th>Status</th><th>Observed</th><th>Actions</th></tr></thead><tbody>{alerts.map((alert) => { const tone = severityTone(alert.severity); const pending = updatingId === alert.alert_id; return <tr key={alert.alert_id}><td><span className={`alert-severity ${tone}`}><i />{tone}<small>{alert.severity}</small></span></td><td><strong>{alert.title}</strong><span>{alert.message}</span></td><td><code>{alert.rule.id}</code><span>v{alert.rule.version}</span></td><td><strong>{alert.entities.host ?? "Unknown host"}</strong><span>{alert.entities.source_ip ?? "No source IP"}</span></td><td>{alert.mitre.technique ? <span className="alert-mitre"><strong>{alert.mitre.technique}</strong>{alert.mitre.tactic}</span> : "Not mapped"}</td><td><span className={`alert-status ${alert.status}`}>{statusLabel(alert.status)}</span></td><td><time>{formatTimestamp(alert["@timestamp"])}</time></td><td><div className="alert-actions"><button disabled={pending || alert.status !== "open"} onClick={() => void applyAction(alert, "acknowledge")}>Acknowledge</button><button disabled={pending || alert.status === "dismissed"} onClick={() => void applyAction(alert, "dismiss")}>Dismiss</button><button className="escalate" disabled={pending || alert.status === "escalated"} onClick={() => void applyAction(alert, "escalate")}>Escalate</button></div></td></tr>; })}</tbody></table></div>}
      </section>
    </div>
  );
}
