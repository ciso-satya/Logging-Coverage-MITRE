import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, isSnapshot } from "../api";
import Matrix from "../components/Matrix";
import { Legend, STATUS_META, STATUS_ORDER, StatusIcon } from "../components/Status";
import TechniqueDrawer from "../components/TechniqueDrawer";
import type { Matrix as MatrixT, Status } from "../types";

export default function HeatmapPage() {
  const [params, setParams] = useSearchParams();
  const [matrix, setMatrix] = useState<MatrixT | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [showSubs, setShowSubs] = useState<"collapsed" | "expanded" | "hidden">("collapsed");
  const [statusFilter, setStatusFilter] = useState<Set<Status>>(new Set(STATUS_ORDER));
  const [platforms, setPlatforms] = useState<string[] | null>(null);
  const selected = params.get("t");

  const load = useCallback(() => {
    setErr(null);
    api
      .matrix(platforms)
      .then(setMatrix)
      .catch((e) => setErr(String(e.message || e)));
  }, [platforms]);
  useEffect(load, [load]);

  const select = (id: string | null) => {
    const p = new URLSearchParams(params);
    if (id) p.set("t", id);
    else p.delete("t");
    setParams(p, { replace: true });
  };

  const togglePlatform = (p: string) => {
    if (!matrix) return;
    const current = platforms ?? matrix.platforms;
    const next = current.includes(p) ? current.filter((x) => x !== p) : [...current, p];
    setPlatforms(next.length === matrix.all_platforms.length ? null : next);
  };

  const toggleStatus = (s: Status) => {
    setStatusFilter((prev) => {
      const n = new Set(prev);
      if (n.size === STATUS_ORDER.length) return new Set([s]);
      if (n.has(s)) n.delete(s);
      else n.add(s);
      return n.size ? n : new Set(STATUS_ORDER);
    });
  };

  const sum = matrix?.summary;
  const tiles = useMemo(() => {
    if (!sum) return [];
    return STATUS_ORDER.map((s) => ({ status: s, count: sum.counts[s], pct: sum.percent[s] }));
  }, [sum]);

  if (err) return <div className="notice error">Could not load the matrix: {err}</div>;
  if (!matrix) return <div className="loading">Loading ATT&amp;CK matrix…</div>;
  if (!matrix.attack)
    return (
      <div className="card">
        <h2>ATT&amp;CK knowledge base not imported yet</h2>
        <p className="secondary">Go to Settings → ATT&amp;CK data and import the Enterprise matrix from MITRE.</p>
      </div>
    );

  const noConnections = matrix.connections.length === 0;
  const activePlatforms = platforms ?? matrix.platforms;

  return (
    <>
      <div className="page-head">
        <h1>Logging &amp; detection coverage heatmap</h1>
        <span className="sub">
          Enterprise ATT&amp;CK v{matrix.attack.version} · {sum!.techniques_parent} techniques, {sum!.techniques_total - sum!.techniques_parent} sub-techniques · {matrix.connections.length} connection{matrix.connections.length === 1 ? "" : "s"}
        </span>
      </div>

      {noConnections && !isSnapshot && (
        <div className="notice warn" style={{ marginBottom: 12 }}>
          No enabled connections. Add a SIEM connection under <b>Settings</b> to populate the heatmap.
        </div>
      )}

      <div className="tiles">
        {tiles.map((t) => (
          <div
            key={t.status}
            className={`tile clickable${statusFilter.size !== STATUS_ORDER.length && statusFilter.has(t.status) ? " on" : ""}`}
            onClick={() => toggleStatus(t.status)}
            title={STATUS_META[t.status].hint}
            role="button"
          >
            <div className="label">
              <StatusIcon status={t.status} /> {STATUS_META[t.status].label}
            </div>
            <div className="value">{t.count}</div>
            <div className="sub">{t.pct}% of techniques (incl. sub-techniques)</div>
          </div>
        ))}
        <div className="tile">
          <div className="label">Telemetry</div>
          <div className="value">{sum!.mitre_log_sources_available}</div>
          <div className="sub">ATT&amp;CK log sources available from {sum!.log_sources_mapped} mapped feeds{sum!.log_sources_unmapped ? ` (${sum!.log_sources_unmapped} unmapped)` : ""}</div>
        </div>
        <div className="tile">
          <div className="label">Rules</div>
          <div className="value">{sum!.rules_mapped}</div>
          <div className="sub">enabled rules mapped to techniques</div>
        </div>
      </div>

      <div className="filters">
        <input className="input grow" placeholder="Search technique id or name…" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search techniques" />
        <div className="segmented" role="group" aria-label="Sub-techniques">
          {(["collapsed", "expanded", "hidden"] as const).map((m) => (
            <button key={m} className={showSubs === m ? "on" : ""} onClick={() => setShowSubs(m)}>
              Sub-techniques: {m}
            </button>
          ))}
        </div>
        {statusFilter.size !== STATUS_ORDER.length && (
          <button className="btn sm" onClick={() => setStatusFilter(new Set(STATUS_ORDER))}>
            Clear status filter
          </button>
        )}
        <a className="btn sm" href={`/api/coverage/navigator-layer${platforms ? `?platforms=${encodeURIComponent(platforms.join(","))}` : ""}`} download hidden={isSnapshot}>
          ⬇ Navigator layer
        </a>
        <a className="btn sm" href={`/api/export/snapshot.html${platforms ? `?platforms=${encodeURIComponent(platforms.join(","))}` : ""}`} download hidden={isSnapshot}>
          ⬇ HTML snapshot
        </a>
      </div>
      <div className="filters">
        <span className="small muted">Platforms:</span>
        <div className="chips" role="group" aria-label="Platform filter">
          {matrix.all_platforms.map((p) => (
            <button key={p} className={`chip${activePlatforms.includes(p) ? " on" : ""}`} onClick={() => togglePlatform(p)} disabled={isSnapshot}>
              {p}
            </button>
          ))}
          {platforms && !isSnapshot && (
            <button className="chip" onClick={() => setPlatforms(null)}>
              reset
            </button>
          )}
        </div>
      </div>

      <Matrix matrix={matrix} statusFilter={statusFilter} search={search} showSubs={showSubs} selected={selected} onSelect={(id) => select(id)} />
      <Legend />

      {selected && <TechniqueDrawer id={selected} platforms={platforms} onClose={() => select(null)} onNavigate={(id) => select(id)} />}
    </>
  );
}
