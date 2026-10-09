import type { Status } from "../types";

export const STATUS_ORDER: Status[] = ["covered", "logs_no_rules", "rules_no_logs", "missing_logs", "no_detection_data"];

export const STATUS_META: Record<Status, { label: string; glyph: string; color: string; hint: string }> = {
  covered: { label: "Logs + rules", glyph: "✓", color: "var(--status-good)", hint: "Required telemetry is collected and at least one enabled rule maps to this technique." },
  logs_no_rules: { label: "Logs, no rules", glyph: "◐", color: "var(--status-warning)", hint: "Telemetry is collected but no enabled detection rule maps to this technique." },
  rules_no_logs: { label: "Rules, no logs", glyph: "!", color: "var(--status-serious)", hint: "A rule exists but none of the log sources ATT&CK analytics need are collected." },
  missing_logs: { label: "Missing logs", glyph: "✕", color: "var(--status-critical)", hint: "No required telemetry is collected and no rule maps to this technique." },
  no_detection_data: { label: "No ATT&CK analytics", glyph: "–", color: "var(--status-neutral)", hint: "ATT&CK lists no analytics for this technique on the selected platforms." },
};

export function StatusIcon({ status, title }: { status: Status; title?: string }) {
  const m = STATUS_META[status];
  return (
    <span className={`status-icon ${status}`} title={title ?? m.label} aria-label={m.label} role="img">
      {m.glyph}
    </span>
  );
}

export function StatusPill({ status }: { status: Status }) {
  const m = STATUS_META[status];
  return (
    <span className={`status-pill ${status}`}>
      <StatusIcon status={status} /> {m.label}
    </span>
  );
}

export function Legend() {
  return (
    <div className="legend" aria-label="Legend">
      {STATUS_ORDER.map((s) => (
        <span className="item" key={s} title={STATUS_META[s].hint}>
          <StatusIcon status={s} /> {STATUS_META[s].label}
        </span>
      ))}
      <span className="item muted">Click a technique for details · ▸ expands sub-techniques</span>
    </div>
  );
}

export function StatusBar({ counts, total }: { counts: Record<Status, number>; total?: number }) {
  const t = total ?? STATUS_ORDER.reduce((a, s) => a + (counts[s] || 0), 0);
  if (!t) return <div className="bar" />;
  return (
    <div className="bar" role="img" aria-label={STATUS_ORDER.map((s) => `${STATUS_META[s].label}: ${counts[s] || 0}`).join(", ")}>
      {STATUS_ORDER.map((s) => (counts[s] ? <span key={s} className={s} style={{ width: `${(100 * counts[s]) / t}%` }} /> : null))}
    </div>
  );
}
