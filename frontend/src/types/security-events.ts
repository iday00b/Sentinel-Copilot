export type EventField = string | string[];

export interface SecurityEvent {
  "@timestamp"?: string;
  message?: string;
  event?: {
    action?: string;
    category?: EventField;
    dataset?: string;
    kind?: string;
    outcome?: string;
    provider?: string;
    severity?: number;
    type?: EventField;
  };
  host?: {
    hostname?: string;
    ip?: EventField;
    name?: string;
  };
  observer?: {
    name?: string;
    type?: string;
  };
  related?: {
    ip?: EventField;
    user?: EventField;
  };
  rule?: {
    id?: string;
    name?: string;
  };
  source?: {
    ip?: EventField;
    port?: number;
  };
  user?: {
    domain?: string;
    id?: string;
    name?: string;
  };
}

export interface SecurityEventsResponse {
  events: SecurityEvent[];
}
