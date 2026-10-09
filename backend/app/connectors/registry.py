from __future__ import annotations

from .base import BaseConnector
from .cribl import CriblConnector
from .crowdstrike import CrowdStrikeConnector
from .demo import DemoConnector
from .file_import import FileImportConnector
from .mcp import MCPConnector
from .splunk import SplunkConnector

CONNECTORS: dict[str, type[BaseConnector]] = {
    c.type: c
    for c in (
        SplunkConnector,
        CrowdStrikeConnector,
        CriblConnector,
        MCPConnector,
        FileImportConnector,
        DemoConnector,
    )
}


def get_connector_class(conn_type: str) -> type[BaseConnector]:
    try:
        return CONNECTORS[conn_type]
    except KeyError as exc:
        raise ValueError(f"Unknown connector type: {conn_type}") from exc


def build_connector(conn_type: str, config: dict, secrets: dict) -> BaseConnector:
    return get_connector_class(conn_type)(config, secrets)


def schemas() -> list[dict]:
    return [c.schema() for c in CONNECTORS.values()]
