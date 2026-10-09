import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { STATUS_META, StatusIcon } from "../components/Status";
import type { Gaps, TechniqueCell } from "../types";

function TechTable({ rows, showMissing, showRules }: { rows: TechniqueCell[]; showMissing?: boolean; showRules?: boolean }) {
  const nav = useNavigate();
  if (rows.length === 0) return <div className="empty">Nothing here.</div>;
  return (
    <div style={{ maxHeight: 520, overflow: "auto" }}>
      <table className="table">
        <thead>
          <tr>
            <th>Technique</th>
            <th>Tactics</th>
            {showMissing && <th>Log sources to onboard</th>}
            {showRules && <th className="num">Rules</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((t) => (
            <tr key={t.attack_id}>
              <td>
                <span className="tech-link" onClick={() => nav(`/heatmap?t=${t.attack_id}`)}>
                  <StatusIcon status={t.status} /> <span className="mono">{t.attack_id}</span> {t.name}
                </span>
              </td>
              <td className="small secondary">{t.tactics.join(", ")}</td>
              {showMissing && <td className="small mono">{t.logs.missing.slice(0, 5).join(", ")}{t.logs.missing.length > 5 ? " …" : ""}</td>}
              {showRules && <td className="num">{t.rules.count}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function GapsPage() {
  const [g, setG] = useState<Gaps | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const nav = useNavigate();
  useEffect(() => {
    api.gaps().then(setG).catch((e) => setErr(String(e.message || e)));
  }, []);
  if (err) return <div className="notice error">{err}</div>;
  if (!g) return <div className="loading">Computing gaps…</div>;
  const s = g.summary;
  return (
    <>
      <div className="page-head">
        <h1>Gap analysis</h1>
        <span className="sub">What to onboard and what to write next</span>
      </div>

      <div className="grid2">
        <div className="card">
          <h2>
            <StatusIcon status="missing_logs" /> 1. Techniques missing logs ({g.missing_logs.length})
          </h2>
          <p className="small secondary">No analytic for these techniques can run: none of the log sources ATT&amp;CK lists are collected. Includes {s.counts.rules_no_logs} technique(s) that have a rule but no telemetry ({STATUS_META.rules_no_logs.label}).</p>
          <TechTable rows={g.missing_logs} showMissing showRules />
        </div>
        <div className="card">
          <h2>
            <StatusIcon status="logs_no_rules" /> 2. Logs available, no rules ({g.logs_no_rules.length})
          </h2>
          <p className="small secondary">Telemetry is already in the SIEM. Writing or enabling a rule here is the cheapest coverage win.</p>
          <TechTable rows={g.logs_no_rules} />
        </div>
      </div>

      <div className="card">
        <h2>Highest-impact log sources to onboard</h2>
        <p className="small secondary">Each missing ATT&amp;CK log source, ranked by how many red/orange techniques it would move toward coverage.</p>
        <table className="table">
          <thead>
            <tr>
              <th>ATT&amp;CK log source</th>
              <th className="num">Techniques unlocked</th>
              <th className="num">…of which already have rules</th>
              <th>Examples</th>
            </tr>
          </thead>
          <tbody>
            {g.log_source_impact.map((r) => (
              <tr key={r.log_source}>
                <td className="mono">{r.log_source}</td>
                <td className="num">{r.techniques}</td>
                <td className="num">{r.with_rules}</td>
                <td className="small">
                  {r.technique_ids.slice(0, 6).map((id) => (
                    <span key={id} className="tech-link mono" style={{ marginRight: 6 }} onClick={() => nav(`/heatmap?t=${id}`)}>
                      {id}
                    </span>
                  ))}
                  {r.technique_ids.length > 6 ? `+${r.technique_ids.length - 6}` : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h2>
          <StatusIcon status="covered" /> 3. Covered: logs and rules ({g.covered.length})
        </h2>
        <TechTable rows={g.covered} showRules />
      </div>
    </>
  );
}
