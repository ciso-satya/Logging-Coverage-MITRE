export type Status = "covered" | "logs_no_rules" | "rules_no_logs" | "missing_logs" | "no_detection_data";

export interface LogsEval {
  state: "full" | "partial" | "none";
  score: number;
  analytics: number;
  satisfied: number;
  matched: string[];
  missing: string[];
  no_analytics: boolean;
}

export interface RulesEval {
  count: number;
  direct: number;
  related: number;
  related_via: string;
  ids: number[];
}

export interface TechniqueCell {
  attack_id: string;
  name: string;
  url: string;
  is_subtechnique: boolean;
  parent: string | null;
  platforms: string[];
  tactics: string[];
  status: Status;
  logs: LogsEval;
  rules: RulesEval;
}

export interface TacticCol {
  attack_id: string;
  name: string;
  shortname: string;
  url: string;
  techniques: string[];
  counts: Record<Status, number>;
}

export interface Summary {
  techniques_total: number;
  techniques_parent: number;
  counts: Record<Status, number>;
  parent_counts: Record<Status, number>;
  percent: Record<Status, number>;
  log_sources_total: number;
  log_sources_mapped: number;
  log_sources_unmapped: number;
  mitre_log_sources_available: number;
  rules_total: number;
  rules_mapped: number;
}

export interface ConnectionSummary {
  id: number;
  name: string;
  type: string;
  last_sync_at: string | null;
  last_sync_status: string;
}

export interface Matrix {
  attack: { version: string; domain: string; imported_at: string | null; technique_count: number; subtechnique_count: number; analytic_count: number } | null;
  platforms: string[];
  all_platforms: string[];
  tactics: TacticCol[];
  techniques: Record<string, TechniqueCell>;
  children: Record<string, string[]>;
  summary: Summary;
  connections: ConnectionSummary[];
  status_labels: Record<Status, string>;
}

export interface LogSourceRef {
  data_component: string;
  data_component_name: string;
  name: string;
  channel: string;
  available: boolean;
  providers: { connection: string; log_source: string; log_source_id: number }[];
}

export interface AnalyticDetail {
  attack_id: string;
  name: string;
  description: string;
  url: string;
  platforms: string[];
  in_scope: boolean;
  satisfied: boolean;
  log_sources: LogSourceRef[];
  mutable_elements: { field: string; description: string }[];
}

export interface RuleItem {
  id: number;
  name: string;
  connection: string;
  severity: string;
  techniques: string[];
  url: string;
  description: string;
  relation: string;
}

export interface TechniqueDetail {
  attack_id: string;
  name: string;
  description: string;
  detection: string;
  url: string;
  is_subtechnique: boolean;
  parent: string | null;
  children: string[];
  platforms: string[];
  tactics: string[];
  data_components: string[];
  status: Status;
  logs: LogsEval;
  rules: RulesEval & { items: RuleItem[] };
  strategies: { attack_id: string; name: string; description: string; url: string }[];
  analytics: AnalyticDetail[];
}

export interface Gaps {
  summary: Summary;
  status_labels: Record<Status, string>;
  missing_logs: TechniqueCell[];
  logs_no_rules: TechniqueCell[];
  covered: TechniqueCell[];
  no_detection_data: TechniqueCell[];
  log_source_impact: { log_source: string; techniques: number; with_rules: number; technique_ids: string[] }[];
}

export interface FieldSpec {
  name: string;
  label: string;
  type: string;
  required: boolean;
  secret: boolean;
  default: unknown;
  help: string;
  options: string[];
  placeholder: string;
}

export interface ConnectorType {
  type: string;
  label: string;
  description: string;
  docs_url: string;
  provides_rules: boolean;
  fields: FieldSpec[];
}

export interface Connection {
  id: number;
  name: string;
  type: string;
  type_label: string;
  enabled: boolean;
  config: Record<string, unknown>;
  secrets_set: string[];
  created_at: string | null;
  last_sync_at: string | null;
  last_sync_status: string;
  last_sync_message: string;
  log_source_count?: number;
  rule_count?: number;
}

export interface MappedLogSource {
  id: number;
  connection_id: number;
  connection: string;
  connection_type: string;
  name: string;
  kind: string;
  vendor: string;
  product: string;
  event_count: number;
  mitre_log_sources: string[];
  matched_rules: string[];
}

export interface MappingOverride {
  id: number;
  pattern: string;
  field: string;
  mitre_log_sources: string[];
  note: string;
  enabled: boolean;
}

export interface AttackStatus {
  imported: boolean;
  version?: string;
  imported_at?: string;
  tactics?: number;
  techniques?: number;
  subtechniques?: number;
  analytics?: number;
  detection_strategies?: number;
  log_source_names?: number;
  source_url?: string;
}

export interface MitreLogSourceName {
  name: string;
  strategies: number;
  data_components: string[];
  example_channels: string[];
}
