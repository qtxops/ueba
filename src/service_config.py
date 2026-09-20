"""Environment-backed configuration for the SentinelUEBA service layer."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ServiceSettings:
    database_path: Path = ROOT / "artifacts" / "sentinel_ueba.db"
    artifact_dir: Path = ROOT / "artifacts" / "live"
    secret_key: str = "development-only-change-me"
    token_minutes: int = 60
    admin_username: str = "admin"
    admin_password: str = ""
    require_secure_config: bool = False

    @classmethod
    def from_environment(cls) -> "ServiceSettings":
        return cls(
            database_path=Path(os.getenv("SENTINEL_DB_PATH", ROOT / "artifacts" / "sentinel_ueba.db")),
            artifact_dir=Path(os.getenv("SENTINEL_ARTIFACT_DIR", ROOT / "artifacts" / "live")),
            secret_key=os.getenv("SENTINEL_SECRET_KEY", "development-only-change-me"),
            token_minutes=int(os.getenv("SENTINEL_TOKEN_MINUTES", "60")),
            admin_username=os.getenv("SENTINEL_ADMIN_USERNAME", "admin"),
            admin_password=os.getenv("SENTINEL_ADMIN_PASSWORD", ""),
            require_secure_config=os.getenv("SENTINEL_REQUIRE_SECURE_CONFIG", "0").lower()
            in {"1", "true", "yes"},
        )

    @property
    def production_safe(self) -> bool:
        return (
            self.secret_key != "development-only-change-me"
            and not self.secret_key.startswith("replace-")
            and len(self.secret_key) >= 32
        )
