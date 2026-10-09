import { useCallback, useEffect, useState } from "react";
import { api, fmtDate } from "../api";
import type { AttackStatus, Connection, ConnectorType, FieldSpec, MappingOverride, MitreLogSourceName } from "../types";

/* ------------------------------------------------------------------ connection form */

function Field({ f, value, onChange, secretSet }: { f: FieldSpec; value: unknown; onChange: (v: unknown) => void; secretSet: boolean }) {
  const common = { id: `f-${f.name}`, className: "input" };
  let input;
  if (f.type === "bool") {
    input = (
      <label className="check">
        <input type="checkbox" checked={!!value} onChange={(e) => onChange(e.target.checked)} /> {f.help || "Enabled"}
      </label>
    );
  } else if (f.type === "select") {
    input = (
      <select {...common} value={String(value ?? f.default ?? "")} onChange={(e) => onChange(e.target.value)}>
        {f.options.map((o) => (
          <option key={o} value={o}>{o}</option>
        ))}
      </select>
    );
  } else if (f.type === "textarea") {
    input = <textarea {...common} value={String(value ?? "")} placeholder={f.placeholder} onChange={(e) => onChange(e.target.value)} />;
  } else {
    input = (
      <input
        {...common}
        type={f.type === "password" ? "password" : f.type === "number" ? "number" : "text"}
        value={String(value ?? "")}
        placeholder={f.secret && secretSet ? "•••••••• (stored; leave blank to keep)" : f.placeholder}
        autoComplete="off"
        onChange={(e) => onChange(e.target.value)}
      />
    );
  }
  return (
    <label className={`field${f.type === "textarea" ? " full" : ""}`} htmlFor={`f-${f.name}`}>
      <span className="lbl">
        {f.label}
        {f.required && <span style={{ color: "var(--status-critical)" }}> *</span>}
      </span>
      {input}
      {f.type !== "bool" && f.help && <span className="help">{f.help}</span>}
    </label>
  );
}

function ConnectionForm({ types, initial, onSaved, onCancel }: { types: ConnectorType[]; initial?: Connection; onSaved: () => void; onCancel: () => void }) {
  const [type, setType] = useState(initial?.type ?? types[0]?.type ?? "splunk");
  const [name, setName] = useState(initial?.name ?? "");
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [values, setValues] = useState<Record<string, unknown>>(initial?.config ?? {});
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);
  const spec = types.find((t) => t.type === type);

  useEffect(() => {
    if (!initial) {
      const defaults: Record<string, unknown> = {};
      spec?.fields.forEach((f) => {
        if (f.default !== null && f.default !== undefined) defaults[f.name] = f.default;
      });
      setValues(defaults);
      if (!name && spec) setName(spec.label);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type]);

  const body = () => {
    const config: Record<string, unknown> = {};
    const secrets: Record<string, unknown> = {};
    spec?.fields.forEach((f) => {
      const v = values[f.name];
      if (f.secret) {
        if (v !== undefined && v !== "") secrets[f.name] = v;
      } else config[f.name] = v ?? f.default ?? "";
    });
    return { name, type, enabled, config, secrets };
  };

  const test = async () => {
    setBusy("test");
    setResult(null);
    try {
      const r = initial && Object.keys(body().secrets).length === 0 && JSON.stringify(body().config) === JSON.stringify(initial.config) ? await api.testConnection(initial.id) : await api.testUnsaved(body());
      setResult(r);
    } catch (e) {
      setResult({ ok: false, message: String((e as Error).message) });
    } finally {
      setBusy(null);
    }
  };
  const save = async () => {
    setBusy("save");
    try {
      if (initial) await api.updateConnection(initial.id, body());
      else await api.createConnection(body());
      onSaved();
    } catch (e) {
      setResult({ ok: false, message: String((e as Error).message) });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="card">
      <h2>{initial ? `Edit connection: ${initial.name}` : "New connection"}</h2>
      <div className="form-grid" style={{ marginTop: 10 }}>
        <label className="field">
          <span className="lbl">Type</span>
          <select className="input" value={type} onChange={(e) => setType(e.target.value)} disabled={!!initial}>
            {types.map((t) => (
              <option key={t.type} value={t.type}>{t.label}</option>
            ))}
          </select>
          {spec && <span className="help">{spec.description} {spec.docs_url && <a href={spec.docs_url} target="_blank" rel="noreferrer">Docs ↗</a>}</span>}
        </label>
        <label className="field">
          <span className="lbl">Name *</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
          <label className="check" style={{ marginTop: 6 }}>
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled (included in coverage)
          </label>
        </label>
        {spec?.fields.map((f) => (
          <Field key={f.name} f={f} value={values[f.name]} secretSet={!!initial?.secrets_set.includes(f.name)} onChange={(v) => setValues((p) => ({ ...p, [f.name]: v }))} />
        ))}
      </div>
      {result && <div className={`notice ${result.ok ? "ok" : "error"}`} style={{ marginTop: 10 }}>{result.message}</div>}
      <div className="row" style={{ marginTop: 12 }}>
        <button className="btn" onClick={test} disabled={!!busy}>{busy === "test" ? "Testing…" : "Test connection"}</button>
        <button className="btn primary" onClick={save} disabled={!!busy || !name}>{busy === "save" ? "Saving…" : "Save"}</button>
        <button className="btn ghost" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ connections list */

function Connections() {
  const [types, setTypes] = useState<ConnectorType[]>([]);
  const [conns, setConns] = useState<Connection[]>([]);
  const [editing, setEditing] = useState<Connection | "new" | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [flash, setFlash] = useState<string | null>(null);
  const load = useCallback(() => api.connections().then(setConns).catch(() => setConns([])), []);
  useEffect(() => {
    api.connectorTypes().then(setTypes).catch(() => setTypes([]));
    load();
  }, [load]);

  const sync = async (c: Connection) => {
    setBusy(c.id);
    setFlash(null);
    try {
      const r = await api.syncConnection(c.id);
      setFlash(r.ok ? `${c.name}: synced ${r.log_sources} log sources and ${r.rules} rules${r.warnings?.length ? ` (warnings: ${r.warnings.join("; ")})` : ""}` : `${c.name}: ${r.error}`);
    } catch (e) {
      setFlash(String((e as Error).message));
    } finally {
      setBusy(null);
      load();
    }
  };
  const remove = async (c: Connection) => {
    if (!confirm(`Delete connection "${c.name}" and its imported inventory?`)) return;
    await api.deleteConnection(c.id);
    load();
  };
  const toggle = async (c: Connection) => {
    await api.updateConnection(c.id, { name: c.name, type: c.type, enabled: !c.enabled, config: c.config, secrets: {} });
    load();
  };

  return (
    <>
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 10 }}>
        <div>
          <h2>Connections</h2>
          <p className="small secondary">SIEMs and pipelines the coverage is computed from. Secrets are encrypted at rest.</p>
        </div>
        <div className="row">
          <button className="btn" onClick={async () => { setBusy(-1); await api.syncAll(); setBusy(null); load(); }} disabled={busy !== null}>{busy === -1 ? "Syncing…" : "Sync all"}</button>
          <button className="btn primary" onClick={() => setEditing("new")}>+ Add connection</button>
        </div>
      </div>
      {flash && <div className="notice" style={{ marginBottom: 10 }}>{flash}</div>}
      {editing && <div style={{ marginBottom: 12 }}><ConnectionForm types={types} initial={editing === "new" ? undefined : editing} onSaved={() => { setEditing(null); load(); }} onCancel={() => setEditing(null)} /></div>}
      <div className="conn-list">
        {conns.length === 0 && <div className="empty">No connections yet.</div>}
        {conns.map((c) => (
          <div className="conn" key={c.id} style={{ opacity: c.enabled ? 1 : 0.6 }}>
            <div>
              <div className="title">{c.name} <span className="badge">{c.type_label}</span>{!c.enabled && <span className="badge">disabled</span>}</div>
              <div className="state">
                <span className={`dot-state ${c.last_sync_status}`} />
                {c.last_sync_status === "never" ? "Never synced" : `${c.last_sync_status} · ${fmtDate(c.last_sync_at)}`} {c.last_sync_message && `· ${c.last_sync_message}`}
              </div>
              <div className="state">{c.log_source_count ?? 0} log sources · {c.rule_count ?? 0} rules</div>
            </div>
            <div className="actions">
              <button className="btn sm" onClick={() => sync(c)} disabled={busy !== null}>{busy === c.id ? "Syncing…" : "Sync now"}</button>
              <button className="btn sm" onClick={() => setEditing(c)}>Edit</button>
              <button className="btn sm" onClick={() => toggle(c)}>{c.enabled ? "Disable" : "Enable"}</button>
              <button className="btn sm danger" onClick={() => remove(c)}>Delete</button>
            </div>
          </div>
        ))}
      </div>
    </>
  );
}

/* ------------------------------------------------------------------ scope / platforms */

function Scope() {
  const [all, setAll] = useState<string[]>([]);
  const [sel, setSel] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    api.settings().then((s) => { setAll(s.all_platforms); setSel(s.platforms); });
  }, []);
  const current = sel ?? all;
  const toggle = (p: string) => {
    const next = current.includes(p) ? current.filter((x) => x !== p) : [...current, p];
    setSel(next.length === all.length ? null : next);
    setSaved(false);
  };
  return (
    <>
      <h2>Platform scope</h2>
      <p className="small secondary">Only analytics and techniques for these platforms count. Deselect platforms you do not operate (for example macOS or ESXi) so they do not show as gaps.</p>
      <div className="chips" style={{ margin: "8px 0" }}>
        {all.map((p) => (
          <button key={p} className={`chip${current.includes(p) ? " on" : ""}`} onClick={() => toggle(p)}>{p}</button>
        ))}
      </div>
      <div className="row">
        <button className="btn primary" onClick={async () => { await api.saveSettings(sel); setSaved(true); }}>Save scope</button>
        {saved && <span className="small" style={{ color: "var(--status-good)" }}>Saved</span>}
      </div>
    </>
  );
}

/* ------------------------------------------------------------------ ATT&CK data */

function AttackData() {
  const [st, setSt] = useState<AttackStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const load = () => api.attackStatus().then(setSt);
  useEffect(() => { load(); }, []);
  const run = async (force: boolean) => {
    setBusy(true);
    setMsg(null);
    try {
      const r = await api.attackImport(force);
      setMsg(`Imported ATT&CK v${r.version}`);
      load();
    } catch (e) {
      setMsg(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <h2>ATT&amp;CK knowledge base</h2>
      {st?.imported ? (
        <dl className="kv" style={{ margin: "8px 0" }}>
          <dt>Version</dt><dd>Enterprise ATT&amp;CK v{st.version}</dd>
          <dt>Imported</dt><dd>{fmtDate(st.imported_at)}</dd>
          <dt>Content</dt><dd>{st.tactics} tactics · {st.techniques} techniques · {st.subtechniques} sub-techniques · {st.detection_strategies} detection strategies · {st.analytics} analytics · {st.log_source_names} log source names</dd>
          <dt>Source</dt><dd className="small mono" style={{ wordBreak: "break-all" }}>{st.source_url}</dd>
        </dl>
      ) : (
        <p className="small secondary">Not imported yet.</p>
      )}
      {msg && <div className="notice" style={{ margin: "8px 0" }}>{msg}</div>}
      <div className="row">
        <button className="btn primary" onClick={() => run(true)} disabled={busy}>{busy ? "Importing…" : "Download latest from MITRE"}</button>
        <button className="btn" onClick={() => run(false)} disabled={busy}>Re-import cached bundle</button>
      </div>
    </>
  );
}

/* ------------------------------------------------------------------ mapping overrides */

function Mappings() {
  const [rows, setRows] = useState<MappingOverride[]>([]);
  const [names, setNames] = useState<MitreLogSourceName[]>([]);
  const [builtin, setBuiltin] = useState<{ pattern: string; mitre_log_sources: string[]; note: string }[]>([]);
  const [showBuiltin, setShowBuiltin] = useState(false);
  const [pattern, setPattern] = useState("");
  const [field, setField] = useState("any");
  const [pick, setPick] = useState<string[]>([]);
  const [note, setNote] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [nameQ, setNameQ] = useState("");
  const load = () => api.mappings().then(setRows);
  useEffect(() => {
    load();
    api.mitreLogSourceNames().then(setNames);
    api.builtinMappings().then(setBuiltin);
  }, []);
  const add = async () => {
    setErr(null);
    try {
      await api.createMapping({ pattern, field, mitre_log_sources: pick, note });
      setPattern(""); setPick([]); setNote("");
      load();
    } catch (e) {
      setErr(String((e as Error).message));
    }
  };
  return (
    <>
      <h2>Log source mappings</h2>
      <p className="small secondary">
        Feeds are mapped to ATT&amp;CK canonical log source names (as used by ATT&amp;CK analytics) with {builtin.length} built-in regex rules. Add overrides for custom sourcetypes. <a href="#" onClick={(e) => { e.preventDefault(); setShowBuiltin((s) => !s); }}>{showBuiltin ? "Hide" : "Show"} built-in catalog</a>
      </p>
      {showBuiltin && (
        <div style={{ maxHeight: 260, overflow: "auto", marginBottom: 10 }}>
          <table className="table">
            <thead><tr><th>Pattern</th><th>ATT&amp;CK log sources</th><th>Note</th></tr></thead>
            <tbody>{builtin.map((b, i) => <tr key={i}><td className="mono small">{b.pattern}</td><td className="small mono">{b.mitre_log_sources.join(", ")}</td><td className="small">{b.note}</td></tr>)}</tbody>
          </table>
        </div>
      )}
      <div className="form-grid">
        <label className="field"><span className="lbl">Pattern (regex, case-insensitive)</span><input className="input mono" value={pattern} onChange={(e) => setPattern(e.target.value)} placeholder="^acme:custom_audit$" /></label>
        <label className="field"><span className="lbl">Match against</span>
          <select className="input" value={field} onChange={(e) => setField(e.target.value)}>
            {["any", "name", "vendor", "product", "kind"].map((f) => <option key={f}>{f}</option>)}
          </select>
        </label>
        <label className="field"><span className="lbl">Note</span><input className="input" value={note} onChange={(e) => setNote(e.target.value)} /></label>
        <div className="field full">
          <span className="lbl">ATT&amp;CK log sources ({pick.length} selected)</span>
          <input className="input" placeholder="filter names…" value={nameQ} onChange={(e) => setNameQ(e.target.value)} style={{ maxWidth: 280 }} />
          <div className="tags" style={{ maxHeight: 150, overflow: "auto", marginTop: 6 }}>
            {names.filter((n) => !nameQ || n.name.toLowerCase().includes(nameQ.toLowerCase()) || pick.includes(n.name)).map((n) => (
              <button key={n.name} className={`chip${pick.includes(n.name) ? " on" : ""}`} onClick={() => setPick((p) => (p.includes(n.name) ? p.filter((x) => x !== n.name) : [...p, n.name]))}>{n.name}</button>
            ))}
          </div>
        </div>
      </div>
      {err && <div className="notice error" style={{ marginTop: 8 }}>{err}</div>}
      <div className="row" style={{ marginTop: 10 }}>
        <button className="btn primary" disabled={!pattern || pick.length === 0} onClick={add}>Add override</button>
      </div>
      {rows.length > 0 && (
        <table className="table" style={{ marginTop: 12 }}>
          <thead><tr><th>Pattern</th><th>Field</th><th>ATT&amp;CK log sources</th><th>Note</th><th></th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} style={{ opacity: r.enabled ? 1 : 0.5 }}>
                <td className="mono small">{r.pattern}</td>
                <td className="small">{r.field}</td>
                <td className="tags">{r.mitre_log_sources.map((n) => <span className="badge mono" key={n}>{n}</span>)}</td>
                <td className="small">{r.note}</td>
                <td className="row">
                  <button className="btn sm" onClick={async () => { await api.updateMapping(r.id, { ...r, enabled: !r.enabled }); load(); }}>{r.enabled ? "Disable" : "Enable"}</button>
                  <button className="btn sm danger" onClick={async () => { await api.deleteMapping(r.id); load(); }}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

export default function SettingsPage() {
  return (
    <>
      <div className="page-head"><h1>Settings</h1></div>
      <div className="card"><Connections /></div>
      <div className="grid2" style={{ marginTop: 12 }}>
        <div className="card"><Scope /></div>
        <div className="card"><AttackData /></div>
      </div>
      <div className="card" style={{ marginTop: 12 }}><Mappings /></div>
    </>
  );
}
