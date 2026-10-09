from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings, loaded from environment variables prefixed with LCM_."""

    model_config = SettingsConfigDict(env_prefix="LCM_", env_file=".env", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8000
    data_dir: Path = Path("./data")
    secret_key: str | None = None
    attack_stix_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json"
    )
    sync_interval_minutes: int = 0
    seed_demo: bool = True
    # Path of the built frontend (frontend/dist). Served at / when present.
    frontend_dist: Path | None = None

    @property
    def db_path(self) -> Path:
        return self.data_dir / "coverage.db"

    @property
    def attack_cache_path(self) -> Path:
        return self.data_dir / "enterprise-attack.json"


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
