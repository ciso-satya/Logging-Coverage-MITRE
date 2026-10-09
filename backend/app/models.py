from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------------------
# MITRE ATT&CK knowledge base (imported from the official STIX bundle)
# --------------------------------------------------------------------------------------


class AttackMeta(Base):
    __tablename__ = "attack_meta"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(64), default="enterprise-attack")
    version: Mapped[str] = mapped_column(String(32), default="")
    source_url: Mapped[str] = mapped_column(Text, default="")
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    tactic_count: Mapped[int] = mapped_column(Integer, default=0)
    technique_count: Mapped[int] = mapped_column(Integer, default=0)
    subtechnique_count: Mapped[int] = mapped_column(Integer, default=0)
    data_component_count: Mapped[int] = mapped_column(Integer, default=0)
    detection_strategy_count: Mapped[int] = mapped_column(Integer, default=0)
    analytic_count: Mapped[int] = mapped_column(Integer, default=0)
    log_source_name_count: Mapped[int] = mapped_column(Integer, default=0)


class Tactic(Base):
    __tablename__ = "tactics"

    stix_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    attack_id: Mapped[str] = mapped_column(String(16), index=True)  # TA0001
    name: Mapped[str] = mapped_column(String(128))
    shortname: Mapped[str] = mapped_column(String(64), index=True)  # initial-access
    description: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(Text, default="")
    order: Mapped[int] = mapped_column(Integer, default=0)


class Technique(Base):
    __tablename__ = "techniques"

    stix_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    attack_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)  # T1059.001
    name: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text, default="")
    detection: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(Text, default="")
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_attack_id: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    platforms: Mapped[list] = mapped_column(JSON, default=list)
    tactics: Mapped[list] = mapped_column(JSON, default=list)  # tactic shortnames
    data_components: Mapped[list] = mapped_column(JSON, default=list)  # data component names
    detection_strategies: Mapped[list] = mapped_column(JSON, default=list)  # DET ids
    log_source_names: Mapped[list] = mapped_column(JSON, default=list)  # canonical MITRE log source names
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[str] = mapped_column(String(16), default="")


class DataComponent(Base):
    """ATT&CK data component (DC####). Since ATT&CK v18 these carry canonical log sources."""

    __tablename__ = "data_components"

    stix_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    attack_id: Mapped[str] = mapped_column(String(16), index=True, default="")  # DC0032
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(Text, default="")
    # Canonical log sources MITRE lists for this component: [{"name": "WinEventLog:Security", "channel": "EventCode=4688"}]
    log_sources: Mapped[list] = mapped_column(JSON, default=list)
    # Legacy (pre v18) data source grouping, kept for display when present.
    data_source_name: Mapped[str] = mapped_column(String(128), default="")
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)


class DetectionStrategy(Base):
    """ATT&CK detection strategy (DET####) - the detection guidance attached to a technique."""

    __tablename__ = "detection_strategies"

    stix_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    attack_id: Mapped[str] = mapped_column(String(16), index=True)  # DET0103
    name: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(Text, default="")
    techniques: Mapped[list] = mapped_column(JSON, default=list)  # technique attack ids it detects
    analytics: Mapped[list] = mapped_column(JSON, default=list)  # analytic stix ids
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)


class Analytic(Base):
    """ATT&CK analytic (AN####) - one per platform, listing the log sources it needs."""

    __tablename__ = "analytics"

    stix_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    attack_id: Mapped[str] = mapped_column(String(16), index=True)  # AN0286
    name: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(Text, default="")
    strategy_stix_id: Mapped[str | None] = mapped_column(
        String(128), ForeignKey("detection_strategies.stix_id", ondelete="CASCADE"), nullable=True, index=True
    )
    platforms: Mapped[list] = mapped_column(JSON, default=list)
    # [{"data_component": "<stix id>", "data_component_name": "Process Creation",
    #   "name": "WinEventLog:Sysmon", "channel": "EventCode=1"}]
    log_source_refs: Mapped[list] = mapped_column(JSON, default=list)
    mutable_elements: Mapped[list] = mapped_column(JSON, default=list)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)


# --------------------------------------------------------------------------------------
# Connections (SIEM / pipeline integrations) and the inventory pulled from them
# --------------------------------------------------------------------------------------


class Connection(Base):
    __tablename__ = "connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    type: Mapped[str] = mapped_column(String(64), index=True)  # splunk, crowdstrike, cribl, mcp, demo, file
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)  # non-secret settings
    secrets_enc: Mapped[str] = mapped_column(Text, default="")  # Fernet-encrypted JSON of secrets
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_status: Mapped[str] = mapped_column(String(32), default="never")  # never|ok|error|running
    last_sync_message: Mapped[str] = mapped_column(Text, default="")

    log_sources: Mapped[list["LogSource"]] = relationship(
        back_populates="connection", cascade="all, delete-orphan", passive_deletes=True
    )
    rules: Mapped[list["Rule"]] = relationship(
        back_populates="connection", cascade="all, delete-orphan", passive_deletes=True
    )


class LogSource(Base):
    """A log feed observed in a SIEM / pipeline (sourcetype, index, repository, input ...)."""

    __tablename__ = "log_sources"
    __table_args__ = (UniqueConstraint("connection_id", "external_id", name="uq_log_source"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    connection_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("connections.id", ondelete="CASCADE"), index=True
    )
    external_id: Mapped[str] = mapped_column(String(512))
    name: Mapped[str] = mapped_column(String(512))
    kind: Mapped[str] = mapped_column(String(64), default="sourcetype")
    vendor: Mapped[str] = mapped_column(String(128), default="")
    product: Mapped[str] = mapped_column(String(128), default="")
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    # Explicit MITRE log source names assigned by the connector itself (e.g. a file import
    # or an MCP tool that already returns ATT&CK log source names). Bypasses the catalog.
    explicit_log_sources: Mapped[list] = mapped_column(JSON, default=list)

    connection: Mapped[Connection] = relationship(back_populates="log_sources")


class Rule(Base):
    """A detection rule / correlation search / saved alert found in a SIEM."""

    __tablename__ = "rules"
    __table_args__ = (UniqueConstraint("connection_id", "external_id", name="uq_rule"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    connection_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("connections.id", ondelete="CASCADE"), index=True
    )
    external_id: Mapped[str] = mapped_column(String(512))
    name: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    severity: Mapped[str] = mapped_column(String(32), default="")
    query: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(Text, default="")
    techniques: Mapped[list] = mapped_column(JSON, default=list)  # ATT&CK technique ids
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    log_sources: Mapped[list] = mapped_column(JSON, default=list)  # log source names the rule reads
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)

    connection: Mapped[Connection] = relationship(back_populates="rules")


class MappingOverride(Base):
    """User-defined mapping rule: SIEM log source pattern -> ATT&CK canonical log source names."""

    __tablename__ = "mapping_overrides"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pattern: Mapped[str] = mapped_column(String(512))  # case-insensitive regex
    field: Mapped[str] = mapped_column(String(32), default="any")  # any|name|vendor|product|kind
    mitre_log_sources: Mapped[list] = mapped_column(JSON, default=list)  # e.g. ["WinEventLog:Security"]
    note: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AppSetting(Base):
    """Simple key/value store for application-wide settings (e.g. platforms in scope)."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict | list | str | int | None] = mapped_column(JSON, nullable=True)
