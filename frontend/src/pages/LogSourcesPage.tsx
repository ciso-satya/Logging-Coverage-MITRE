import { useEffect, useMemo, useState } from "react";
import { api, fmtNum } from "../api";
import type { MappedLogSource, MitreLogSourceName } from "../types";

export default function LogSourcesPage() {
  const [data, setData] = useState<{ mapped: MappedLogSource[]; unmapped: MappedLogSource[] } | null>(null);
  const [names, setNames] = useState<MitreLogSourceName[]>([]);
  const [q, setQ] = useState("");
  const [tab, setTab] = useState<"feeds" | "mitre">("feeds");
  const [adding, setAdding] = useState<MappedLogSource | null>(null);
  const [pick, setPick] = useState<string[]>([]);
  const [msg, setMsg] = useState<string | null>(null);

  const load = () => api.logSources().then(setData).catch(() => setData({ mapped: [], unmapped: [] }));
  useEffect(() => {
    load();
    api.mitreLogSourceNames().then(setNames).catch(() => setNames([]));
  }, []);

  const all = useMemo(() => (data ? [...data.unmapped, ...data.mapped] : []), [data]);
  const filtered = all.filter((s) => !q || `${s.name} ${s.vendor} ${s.product} ${s.connection} ${s.mitre_log_sources.join(" ")}`.toLowerCase().includes(q.toLowerCase()));
  const available = useMemo(() => new Set(all.flatMap((s) => s.mitre_log_sources)), [all]);

  const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const saveMapping = async () => {
    if (!adding || pick.length === 0) return;
    try {
      await api.createMapping({ pattern: `^${escapeRe(adding.name)}$`, field: "name", mitre_log_sources: pick, note: `Manual mapping for ${adding.name}` });
      setMsg(`Mapped ${adding.name} → ${pick.join(", ")}`);
      setAdding(null);
      setPick([]);
      load();
    } catch (e) {
      setMsg(String((e as Error).message));
    }
  };

  if (!data) return <div className="loading">Loading log sources…</div>;
  return (
    <>
      <div className="page-head">
        <h1>Log sources</h1>
        <span className="sub">
          {all.length} feeds from connected systems · {data.unmapped.length} not yet mapped to an ATT&amp;CK log source · {available.size} of {names.length} ATT&amp;CK log sources available
        </span>
      </div>
      {msg && <div className="notice ok" style={{ marginBottom: 10 }}>{msg}</div>}
      <div className="filters">
        <input className="input grow" placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="segmented">
          <button className={tab === "feeds" ? "on" : ""} onClick={() => setTab("feeds")}>Ingested feeds</button>
          <button className={tab === "mitre" ? "on" : ""} onClick={() => setTab("mitre")}>ATT&amp;CK log sources</button>
        </div>
      </div>

      {tab === "feeds" && (
        <div className="card" style={{ padding: 0 }}>
          <table className="table">
            <thead>
              <tr>
                <th>Feed</th>
                <th>Connection</th>
                <th>Vendor / product</th>
                <th className="num">Events</th>
                <th>Maps to ATT&amp;CK log sources</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((s) => (
                <tr key={s.id}>
                  <td className="mono">{s.name}<div className="muted small" style={{ fontFamily: "var(--font)" }}>{s.kind}</div></td>
                  <td className="small">{s.connection}</td>
                  <td className="small">{[s.vendor, s.product].filter(Boolean).join(" / ")}</td>
                  <td className="num">{s.event_count ? fmtNum(s.event_count) : ""}</td>
                  <td className="tags">
                    {s.mitre_log_sources.length === 0 && <span className="badge" style={{ color: "var(--status-critical)" }}>unmapped</span>}
                    {s.mitre_log_sources.map((n) => <span className="badge mono" key={n}>{n}</span>)}
                  </td>
                  <td>
                    <button className="btn sm" onClick={() => { setAdding(s); setPick([]); }}>Map…</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "mitre" && (
        <div className="card" style={{ padding: 0 }}>
          <table className="table">
            <thead>
              <tr>
                <th>ATT&amp;CK log source</th>
                <th>Available</th>
                <th className="num">Detection strategies</th>
                <th>Data components</th>
                <th>Example channels</th>
              </tr>
            </thead>
            <tbody>
              {names.filter((n) => !q || n.name.toLowerCase().includes(q.toLowerCase())).map((n) => (
                <tr key={n.name}>
                  <td className="mono">{n.name}</td>
                  <td>{available.has(n.name) ? <span style={{ color: "var(--status-good)" }}>✓ yes</span> : <span style={{ color: "var(--status-critical)" }}>✕ no</span>}</td>
                  <td className="num">{n.strategies}</td>
                  <td className="small">{n.data_components.join(", ")}</td>
                  <td className="small muted">{n.example_channels.slice(0, 3).join(" · ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {adding && (
        <>
          <div className="drawer-backdrop" onClick={() => setAdding(null)} />
          <aside className="drawer">
            <div className="drawer-head">
              <div>
                <div className="muted small">Map feed to ATT&amp;CK log sources</div>
                <h2 className="mono">{adding.name}</h2>
              </div>
              <button className="btn ghost close" onClick={() => setAdding(null)}>✕</button>
            </div>
            <div className="drawer-body">
              <p className="small secondary">Pick the canonical ATT&amp;CK log source names this feed provides. A mapping override is created and applied immediately.</p>
              <div className="tags">
                {names.map((n) => (
                  <button key={n.name} className={`chip${pick.includes(n.name) ? " on" : ""}`} onClick={() => setPick((p) => (p.includes(n.name) ? p.filter((x) => x !== n.name) : [...p, n.name]))} title={n.data_components.join(", ")}>
                    {n.name}
                  </button>
                ))}
              </div>
              <div className="row">
                <button className="btn primary" disabled={pick.length === 0} onClick={saveMapping}>Save mapping</button>
                <button className="btn" onClick={() => setAdding(null)}>Cancel</button>
              </div>
            </div>
          </aside>
        </>
      )}
    </>
  );
}
