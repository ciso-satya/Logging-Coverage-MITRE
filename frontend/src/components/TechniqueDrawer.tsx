import { useEffect, useState } from "react";
import { api } from "../api";
import type { TechniqueDetail } from "../types";
import { StatusPill } from "./Status";

export default function TechniqueDrawer({ id, platforms, onClose, onNavigate }: { id: string; platforms: string[] | null; onClose: () => void; onNavigate: (id: string) => void }) {
  const [d, setD] = useState<TechniqueDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    setD(null);
    setErr(null);
    api.technique(id, platforms).then(setD).catch((e) => setErr(String(e.message || e)));
  }, [id, platforms]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" aria-label="Technique details">
        <div className="drawer-head">
          <div>
            <div className="muted small mono">{id}{d?.parent ? <> · sub-technique of <a onClick={() => onNavigate(d.parent!)} href="#">{d.parent}</a></> : null}</div>
            <h2>{d?.name ?? "Loading…"}</h2>
          </div>
          <button className="btn ghost close" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="drawer-body">
          {err && <div className="notice error">{err}</div>}
          {d && (
            <>
              <div className="row">
                <StatusPill status={d.status} />
                <a href={d.url} target="_blank" rel="noreferrer" className="small">View on attack.mitre.org ↗</a>
              </div>
              <dl className="kv">
                <dt>Tactics</dt>
                <dd>{d.tactics.join(", ")}</dd>
                <dt>Platforms</dt>
                <dd>{d.platforms.join(", ")}</dd>
                <dt>Logs</dt>
                <dd>
                  {d.logs.no_analytics ? "No ATT&CK analytics in scope" : d.logs.state === "full" ? `${d.logs.satisfied} of ${d.logs.analytics} analytics fully satisfied` : d.logs.state === "partial" ? `Partial: best analytic ${Math.round(d.logs.score * 100)}% satisfied` : "No required log source collected"}
                </dd>
                <dt>Rules</dt>
                <dd>{d.rules.count} enabled{d.rules.related ? ` (${d.rules.direct} direct, ${d.rules.related} via ${d.rules.related_via})` : ""}</dd>
                {d.data_components.length > 0 && (
                  <>
                    <dt>Data components</dt>
                    <dd className="tags">{d.data_components.map((c) => <span className="badge" key={c}>{c}</span>)}</dd>
                  </>
                )}
              </dl>

              {d.logs.missing.length > 0 && (
                <div className="notice warn">
                  <b>To close the logging gap</b>, onboard: {d.logs.missing.join(", ")}
                </div>
              )}

              <section>
                <div className="section-title">Detection rules ({d.rules.items.length})</div>
                {d.rules.items.length === 0 ? (
                  <div className="muted small">No enabled rule in any connected SIEM maps to {d.attack_id}.</div>
                ) : (
                  <table className="table">
                    <thead><tr><th>Rule</th><th>Source</th><th>Severity</th><th>Mapped via</th></tr></thead>
                    <tbody>
                      {d.rules.items.map((r) => (
                        <tr key={r.id}>
                          <td>{r.url ? <a href={r.url} target="_blank" rel="noreferrer">{r.name}</a> : r.name}<div className="muted small">{r.techniques.join(", ")}</div></td>
                          <td>{r.connection}</td>
                          <td>{r.severity}</td>
                          <td>{r.relation}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </section>

              <section>
                <div className="section-title">ATT&amp;CK analytics &amp; required log sources ({d.analytics.length})</div>
                {d.strategies.map((s) => (
                  <p key={s.attack_id} className="small secondary">
                    <a href={s.url} target="_blank" rel="noreferrer">{s.attack_id}</a> {s.name}
                  </p>
                ))}
                {d.analytics.map((a) => (
                  <div className={`analytic${a.in_scope ? "" : " out"}`} key={a.attack_id}>
                    <div className="head">
                      <a href={a.url} target="_blank" rel="noreferrer" className="mono small">{a.attack_id}</a>
                      <span className="badge">{a.platforms.join(", ") || "any platform"}</span>
                      {a.satisfied ? <span className="badge" style={{ color: "var(--status-good)" }}>✓ satisfied</span> : <span className="badge">not satisfied</span>}
                      {!a.in_scope && <span className="badge">out of platform scope</span>}
                    </div>
                    <div className="desc">{a.description}</div>
                    <div className="ls-list">
                      {a.log_sources.map((ls, i) => (
                        <div className="ls" key={i}>
                          <span className={`mark ${ls.available ? "ok" : "no"}`}>{ls.available ? "✓" : "✕"}</span>
                          <span className="mono">{ls.name}</span>
                          {ls.channel && <span className="ch">{ls.channel}</span>}
                          {ls.data_component_name && <span className="badge">{ls.data_component_name}</span>}
                          {ls.providers.length > 0 && (
                            <span className="prov">
                              ← {ls.providers.slice(0, 3).map((p) => `${p.log_source} (${p.connection})`).join(", ")}
                              {ls.providers.length > 3 ? ` +${ls.providers.length - 3}` : ""}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </section>

              {d.children.length > 0 && (
                <section>
                  <div className="section-title">Sub-techniques</div>
                  <div className="tags">
                    {d.children.map((c) => (
                      <a key={c} href="#" className="badge mono" onClick={(e) => { e.preventDefault(); onNavigate(c); }}>{c}</a>
                    ))}
                  </div>
                </section>
              )}

              <section>
                <div className="section-title">Description</div>
                <details className="more" open={d.description.length < 600}>
                  <summary>Show ATT&amp;CK description</summary>
                  <div className="desc-text">{d.description.replace(/\(Citation:[^)]*\)/g, "")}</div>
                </details>
              </section>
            </>
          )}
          {!d && !err && <div className="loading">Loading…</div>}
        </div>
      </aside>
    </>
  );
}
