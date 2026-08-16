export type AlertStatus = "open" | "acknowledged" | "dismissed" | "escalated";
export type AlertAction = "acknowledge" | "dismiss" | "escalate";

export interface SecurityAlert {
  alert_id: string;
  "@timestamp": string;
  created_at: string;
  updated_at: string;
  status: AlertStatus;
  severity: number;
  title: string;
  message: string;
  rule: {
    id: string;
    name: string;
    version: number;
  };
  source_event: {
    id: string;
    index: string;
    timestamp: string;
  };
  entities: {
    host?: string;
    user?: string;
    source_ip?: string;
  };
  mitre: {
    tactic?: string;
    technique?: string;
  };
}

export interface AlertsResponse {
  alerts: SecurityAlert[];
  total: number;
}

export interface AlertSummary {
  total: number;
  open: number;
  acknowledged: number;
  dismissed: number;
  escalated: number;
  critical: number;
  high: number;
}
