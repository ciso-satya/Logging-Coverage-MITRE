import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";

type Row = { id: number; name: string; connection: string; connection_enabled: boolean; enabled: boolean; severity: string; techniques: string[]; url: string; unmapped: boolean };

export default function RulesPage() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [q, setQ] = useState("");
  const [only, setOnly] = useState<"all" | "unmapped" | "disabled">("all");
  const nav = useNavigate();
  useEffect(() => {
    api.rules().then(setRows).catch(() => setRows([]));
  }, []);
  const filtered = useMemo(() => {
    if (!rows) return [];
    return rows.filter((r) => {
      if (only === "unmapped" && !r.unmapped) return false;
      if (only === "disabled" && r.enabled) return false;
      if (q && !`${r.name} ${r.techniques.join(" ")} ${r.connection}`.toLowerCase().includes(q.toLowerCase())) return false;
      return true;
    });
  }, [rows, q, only]);
  if (!rows) return <div className="loading">Loading rules…</div>;
  const unmapped = rows.filter((r) => r.unmapped).length;
  return (
    <>
      <div className="page-head">
        <h1>Detection rules</h1>
        <span className="sub">{rows.length} rules pulled from connections · {unmapped} without an ATT&amp;CK technique mapping</span>
      </div>
      {unmapped > 0 && (
        <div className="notice warn" style={{ marginBottom: 12 }}>
          {unmapped} rule(s) have no technique id. Add ATT&amp;CK annotations (Splunk ES "MITRE ATT&amp;CK" field, Sigma <code>attack.tXXXX</code> tags, or a <code>T1234</code> id in the rule name) so they count toward coverage.
        </div>
      )}
      <div className="filters">
        <input className="input grow" placeholder="Search rules…" value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="segmented">
          {(["all", "unmapped", "disabled"] as const).map((m) => (
            <button key={m} className={only === m ? "on" : ""} onClick={() => setOnly(m)}>
              {m}
            </button>
          ))}
        </div>
      </div>
      <div className="card" style={{ padding: 0 }}>
        <table className="table">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Connection</th>
              <th>Enabled</th>
              <th>Severity</th>
              <th>Techniques</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr key={r.id}>
                <td>{r.url ? <a href={r.url} target="_blank" rel="noreferrer">{r.name}</a> : r.name}</td>
                <td className="small">{r.connection}{!r.connection_enabled && <span className="badge"> connection disabled</span>}</td>
                <td>{r.enabled ? "yes" : <span style={{ color: "var(--status-critical)" }}>no</span>}</td>
                <td>{r.severity}</td>
                <td className="tags">
                  {r.techniques.map((t) => (
                    <span key={t} className="badge mono tech-link" onClick={() => nav(`/heatmap?t=${t}`)}>{t}</span>
                  ))}
                  {r.unmapped && <span className="badge" style={{ color: "var(--status-critical)" }}>unmapped</span>}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="empty">No rules match.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
