"""Environment-based configuration.

All settings come from environment variables prefixed PREFLIGHT402_ (or a
.env file in the working directory), with defaults that work out of the box:
the free tier needs no keys, so a bare `uvicorn preflight402.api.rest:app`
must boot with nothing set. RPC keys stay None until the milestone that needs
them (M5+ reputation reads, M7 Solana); code that requires one should fail
loudly at use, not at boot.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PREFLIGHT402_",
        env_file=".env",
        env_file_encoding="utf-8",
        # "VAR=" (blank) means unset — otherwise a blank key parses to
        # SecretStr('') and a blank db_path to Path('.'), both breaking the
        # None-means-off / default-fallback contract.
        env_ignore_empty=True,
        extra="ignore",
    )

    environment: Literal["dev", "prod"] = "dev"

    # --- storage ---
    db_path: Path = Path("preflight402.db")

    # --- RPC providers (unused until M5+; None means the feature is off) ---
    alchemy_api_key: SecretStr | None = None
    helius_api_key: SecretStr | None = None

    # --- ERC-8004 reputation (M5) ---
    # The Graph gateway API key for the Agent0 ERC-8004 subgraphs. None means
    # the binding/reputation feature is OFF: the reputation block stays null
    # and no subgraph call is made. Get a key at thegraph.com/studio/apikeys.
    graph_api_key: SecretStr | None = None
    # Subgraph query timeout; a reputation-read failure must never break the
    # free preflight, so this stays short and failures degrade to null.
    graph_timeout_s: float = 8.0

    # --- probing ---
    # Off in prod: refuse to probe private/loopback/metadata targets so a
    # public /preflight can't be turned into a LAN/metadata scanner (SSRF).
    # Turn on for local dev against private x402 endpoints.
    allow_private_targets: bool = False
    probe_timeout_s: float = 10.0
    probe_concurrency: int = 20
    per_host_min_interval_s: float = 60.0
    scheduler_cycle_s: float = 900.0  # 15-minute loop per the build plan
    # The M3 scheduler is deploy-safe OFF: the home LXC must not start bulk
    # probing on redeploy. Turn on explicitly (VPS, or capped home tests).
    scheduler_enabled: bool = False
    # Per-cycle probe budget; 0 = unlimited. Set small (e.g. 50) for
    # conservative testing from a home IP.
    scheduler_max_per_cycle: int = 0

    # --- verdict cache ---
    preflight_cache_ttl_s: float = 300.0  # task 1.5: 5-minute TTL

    # --- public-endpoint hardening ---
    # Per-client-IP token bucket on /preflight (0 disables). Each uncached
    # call makes an outbound probe, so this caps abuse/amplification.
    rate_limit_per_minute: float = 60.0


@lru_cache
def get_settings() -> Settings:
    """Process-wide settings, read once. Tests construct Settings() directly."""
    return Settings()
