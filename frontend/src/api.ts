import type {
  AttackStatus,
  Connection,
  ConnectorType,
  Gaps,
  MappedLogSource,
  MappingOverride,
  Matrix,
  MitreLogSourceName,
  TechniqueDetail,
} from "./types";

declare global {
  interface Window {
    __LCM_SNAPSHOT__?: { matrix: Matrix; gaps: Gaps; details?: Record<string, TechniqueDetail> };
  }
}

export const SNAPSHOT = typeof window !== "undefined" ? window.__LCM_SNAPSHOT__ : undefined;
export const isSnapshot = !!SNAPSHOT;

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(path, { headers: { "Content-Type": "application/json" }, ...init });
  if (!resp.ok) {
    let msg = `${resp.status} ${resp.statusText}`;
    try {
      const body = await resp.json();
      if (body?.detail) msg = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* ignore */
    }
    throw new Error(msg);
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

const q = (platforms?: string[] | null) => (platforms && platforms.length ? `?platforms=${encodeURIComponent(platforms.join(","))}` : "");

export const api = {
  matrix: (platforms?: string[] | null) => (SNAPSHOT ? Promise.resolve(SNAPSHOT.matrix) : req<Matrix>(`/api/coverage/matrix${q(platforms)}`)),
  gaps: (platforms?: string[] | null) => (SNAPSHOT ? Promise.resolve(SNAPSHOT.gaps) : req<Gaps>(`/api/coverage/gaps${q(platforms)}`)),
  technique: (id: string, platforms?: string[] | null) => {
    if (SNAPSHOT) {
      const d = SNAPSHOT.details?.[id];
      return d ? Promise.resolve(d) : Promise.reject(new Error("Technique details are not included in this snapshot"));
    }
    return req<TechniqueDetail>(`/api/coverage/techniques/${id}${q(platforms)}`);
  },
  logSources: () => req<{ mapped: MappedLogSource[]; unmapped: MappedLogSource[]; mitre_log_sources: Record<string, { connection: string; log_source: string }[]> }>("/api/coverage/log-sources"),
  rules: () => req<{ id: number; name: string; connection: string; connection_enabled: boolean; enabled: boolean; severity: string; techniques: string[]; url: string; unmapped: boolean }[]>("/api/coverage/rules"),
  attackStatus: () => req<AttackStatus>("/api/attack/status"),
  attackImport: (force: boolean) => req<{ ok: boolean; version: string }>(`/api/attack/import?force=${force}`, { method: "POST" }),
  mitreLogSourceNames: () => req<MitreLogSourceName[]>("/api/attack/log-sources"),
  connectorTypes: () => req<ConnectorType[]>("/api/connections/types"),
  connections: () => req<Connection[]>("/api/connections"),
  createConnection: (body: unknown) => req<Connection>("/api/connections", { method: "POST", body: JSON.stringify(body) }),
  updateConnection: (id: number, body: unknown) => req<Connection>(`/api/connections/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteConnection: (id: number) => req<void>(`/api/connections/${id}`, { method: "DELETE" }),
  testUnsaved: (body: unknown) => req<{ ok: boolean; message: string; details?: unknown }>("/api/connections/test", { method: "POST", body: JSON.stringify(body) }),
  testConnection: (id: number) => req<{ ok: boolean; message: string; details?: unknown }>(`/api/connections/${id}/test`, { method: "POST" }),
  syncConnection: (id: number) => req<{ ok: boolean; log_sources?: number; rules?: number; error?: string; warnings?: string[] }>(`/api/connections/${id}/sync`, { method: "POST" }),
  syncAll: () => req<unknown[]>("/api/connections/sync-all", { method: "POST" }),
  connectionLogSources: (id: number) => req<{ id: number; name: string; kind: string; vendor: string; product: string; event_count: number }[]>(`/api/connections/${id}/log-sources`),
  connectionRules: (id: number) => req<{ id: number; name: string; enabled: boolean; severity: string; techniques: string[] }[]>(`/api/connections/${id}/rules`),
  mappings: () => req<MappingOverride[]>("/api/mappings"),
  builtinMappings: () => req<{ pattern: string; field: string; mitre_log_sources: string[]; note: string }[]>("/api/mappings/builtin"),
  createMapping: (body: unknown) => req<MappingOverride>("/api/mappings", { method: "POST", body: JSON.stringify(body) }),
  updateMapping: (id: number, body: unknown) => req<MappingOverride>(`/api/mappings/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteMapping: (id: number) => req<void>(`/api/mappings/${id}`, { method: "DELETE" }),
  settings: () => req<{ platforms: string[] | null; all_platforms: string[] }>("/api/settings"),
  saveSettings: (platforms: string[] | null) => req<{ platforms: string[] | null }>("/api/settings", { method: "PUT", body: JSON.stringify({ platforms }) }),
};

export function fmtNum(n: number): string {
  if (n >= 1e9) return (n / 1e9).toFixed(1) + "B";
  if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
  return String(n);
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "never";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
