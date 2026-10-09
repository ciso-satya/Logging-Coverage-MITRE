import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { api, isSnapshot } from "./api";
import type { AttackStatus } from "./types";
import HeatmapPage from "./pages/HeatmapPage";
import GapsPage from "./pages/GapsPage";
import LogSourcesPage from "./pages/LogSourcesPage";
import RulesPage from "./pages/RulesPage";
import SettingsPage from "./pages/SettingsPage";

function useTheme() {
  const [theme, setTheme] = useState<string>(() => {
    try {
      return localStorage.getItem("lcm-theme") || "auto";
    } catch {
      return "auto";
    }
  });
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "auto") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("lcm-theme", theme);
    } catch {
      /* ignore */
    }
  }, [theme]);
  return [theme, setTheme] as const;
}

export default function App() {
  const [theme, setTheme] = useTheme();
  const [attack, setAttack] = useState<AttackStatus | null>(null);
  useEffect(() => {
    if (isSnapshot) return;
    api.attackStatus().then(setAttack).catch(() => setAttack(null));
  }, []);

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="logo" aria-hidden="true">
            <span style={{ background: "var(--status-good)" }} />
            <span style={{ background: "var(--status-warning)" }} />
            <span style={{ background: "var(--status-critical)" }} />
            <span style={{ background: "var(--status-serious)" }} />
          </span>
          ATT&amp;CK Logging Coverage
        </div>
        <nav className="nav" aria-label="Main">
          <NavLink to="/heatmap">Heatmap</NavLink>
          <NavLink to="/gaps">Gaps</NavLink>
          {!isSnapshot && <NavLink to="/log-sources">Log sources</NavLink>}
          {!isSnapshot && <NavLink to="/rules">Rules</NavLink>}
          {!isSnapshot && <NavLink to="/settings">Settings</NavLink>}
        </nav>
        <div className="spacer" />
        <div className="meta">
          {isSnapshot && <span className="badge">Static snapshot</span>}
          {attack?.imported && (
            <span title={`Imported ${attack.imported_at}`}>
              ATT&amp;CK v{attack.version} · {attack.techniques} techniques · {attack.subtechniques} sub-techniques
            </span>
          )}
          <select className="input" value={theme} onChange={(e) => setTheme(e.target.value)} aria-label="Theme" style={{ padding: "3px 6px", fontSize: 12 }}>
            <option value="auto">Auto theme</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </div>
      </header>
      <main className="main">
        <Routes>
          <Route path="/" element={<Navigate to="/heatmap" replace />} />
          <Route path="/heatmap" element={<HeatmapPage />} />
          <Route path="/gaps" element={<GapsPage />} />
          <Route path="/log-sources" element={<LogSourcesPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/settings/*" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/heatmap" replace />} />
        </Routes>
      </main>
    </div>
  );
}
