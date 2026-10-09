import { useState } from "react";
import type { Matrix as MatrixT, Status, TechniqueCell } from "../types";
import { StatusBar, StatusIcon, STATUS_META } from "./Status";
import { Tooltip, type TipState } from "./Tooltip";

interface Props {
  matrix: MatrixT;
  statusFilter: Set<Status>;
  search: string;
  showSubs: "collapsed" | "expanded" | "hidden";
  selected: string | null;
  onSelect: (id: string) => void;
}

function matches(t: TechniqueCell, search: string) {
  if (!search) return true;
  const s = search.toLowerCase();
  return t.attack_id.toLowerCase().includes(s) || t.name.toLowerCase().includes(s);
}

function CellTip({ t }: { t: TechniqueCell }) {
  const m = STATUS_META[t.status];
  return (
    <>
      <div className="t">
        {t.attack_id} · {t.name}
      </div>
      <div>
        <StatusIcon status={t.status} /> {m.label}
      </div>
      <div className="l">
        Logs: {t.logs.state === "full" ? "analytic fully satisfied" : t.logs.state === "partial" ? `partial (${Math.round(t.logs.score * 100)}% of best analytic)` : "none"} · {t.logs.analytics} analytic{t.logs.analytics === 1 ? "" : "s"}
      </div>
      <div className="l">
        Rules: {t.rules.count} {t.rules.related ? `(${t.rules.direct} direct, ${t.rules.related} via ${t.rules.related_via})` : ""}
      </div>
      {t.logs.missing.length > 0 && <div className="l">Missing: {t.logs.missing.slice(0, 4).join(", ")}{t.logs.missing.length > 4 ? " …" : ""}</div>}
    </>
  );
}

export default function Matrix({ matrix, statusFilter, search, showSubs, selected, onSelect }: Props) {
  const [tip, setTip] = useState<TipState | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const toggle = (id: string) => {
    setExpanded((prev) => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  };
  const T = matrix.techniques;

  const visible = (t: TechniqueCell) => statusFilter.has(t.status) && matches(t, search);

  const cell = (t: TechniqueCell, isSub = false) => {
    const kids = isSub ? [] : (matrix.children[t.attack_id] || []).map((k) => T[k]).filter(Boolean);
    const kidsVisible = kids.filter(visible);
    const selfVisible = visible(t);
    if (!selfVisible && kidsVisible.length === 0) return null;
    const open = showSubs === "expanded" || expanded.has(t.attack_id);
    const subCounts = kids.reduce(
      (acc, k) => {
        acc[k.status] = (acc[k.status] || 0) + 1;
        return acc;
      },
      {} as Record<Status, number>,
    );
    return (
      <div key={t.attack_id}>
        <div
          className={`cell ${t.status}${selected === t.attack_id ? " selected" : ""}${!selfVisible ? " dim" : ""}`}
          onClick={() => onSelect(t.attack_id)}
          onMouseEnter={(e) => setTip({ x: e.clientX, y: e.clientY, content: <CellTip t={t} /> })}
          onMouseMove={(e) => setTip((p) => (p ? { ...p, x: e.clientX, y: e.clientY } : p))}
          onMouseLeave={() => setTip(null)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              onSelect(t.attack_id);
            }
          }}
          aria-label={`${t.attack_id} ${t.name}: ${STATUS_META[t.status].label}`}
        >
          <div className="row1">
            <StatusIcon status={t.status} />
            <span className="id">{t.attack_id}</span>
            {t.rules.count > 0 && (
              <span className="badge mono" title={`${t.rules.count} rule(s)`}>
                {t.rules.count}r
              </span>
            )}
            {kids.length > 0 && showSubs !== "hidden" && (
              <button
                className="expand"
                onClick={(e) => {
                  e.stopPropagation();
                  toggle(t.attack_id);
                }}
                aria-expanded={open}
                title={`${kids.length} sub-techniques`}
              >
                {open ? "▾" : "▸"} {kids.length}
              </button>
            )}
          </div>
          <div className="name">{t.name}</div>
          {kids.length > 0 && !open && showSubs !== "hidden" && <StatusBar counts={subCounts} />}
        </div>
        {kids.length > 0 && open && showSubs !== "hidden" && <div className="subcells">{kids.map((k) => cell(k, true))}</div>}
      </div>
    );
  };

  return (
    <>
      <div className="matrix-wrap">
        <div className="matrix" role="table" aria-label="ATT&CK coverage matrix">
          {matrix.tactics.map((tac) => {
            const items = tac.techniques.map((id) => T[id]).filter(Boolean);
            return (
              <div className="col" key={tac.shortname} role="columnheader">
                <div className="col-head">
                  <div className="name" title={tac.name}>
                    {tac.name}
                  </div>
                  <div className="count">
                    {items.length} techniques · <span className="tabular">{tac.counts.covered}</span> covered
                  </div>
                  <StatusBar counts={tac.counts} />
                </div>
                <div className="col-body">{items.map((t) => cell(t))}</div>
              </div>
            );
          })}
        </div>
      </div>
      <Tooltip tip={tip} />
    </>
  );
}
