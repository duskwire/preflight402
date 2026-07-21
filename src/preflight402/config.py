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

    # --- Sybil filter (M6; needs alchemy_api_key, None keeps it off) ---
    alchemy_timeout_s: float = 5.0
    # Uncached first-funder lookups allowed per preflight pass; 0 = unlimited.
    # Funding facts cache permanently, so a big agent (hundreds of reviewers)
    # converges across passes instead of stalling one request for minutes.
    sybil_max_lookups_per_pass: int = 40
    # Parallel in-flight Alchemy calls (free tier allows 25 rps / 500 CUPS).
    sybil_concurrency: int = 8
    # Wall-clock ceiling for one pass's RPC phase; <= 0 disables the ceiling.
    # Whatever resolved before the deadline stays cached; the rest retries.
    sybil_pass_timeout_s: float = 12.0
    # Process-wide daily ceiling on service-path funding lookups (0 = uncapped).
    # A public /preflight caller who keeps forcing cache misses against a
    # feedback-rich agent must not be able to drain the Alchemy CU budget:
    # 5000/day ≈ 0.75M CU/day worst case, comfortably inside the free tier.
    # Deliberate operator backfills (the CLI passes an explicit max_lookups)
    # bypass this cap.
    sybil_daily_lookup_cap: int = 5000
    # Funder-ancestry generations to explore when clustering (>= 1). Depth 1
    # clusters by direct first funder only; the default walks two further
    # generations so clusters form by shared funding ROOT — a one-hop
    # intermediary wallet per Sybil must not defeat the filter. Every fact is
    # cached permanently, so deeper exploration converges to cache hits.
    sybil_ancestry_depth: int = 3
    # OPT-IN fan-out hub heuristic: a funder whose funded reviewers span at
    # least this many DISTINCT agents is treated as infrastructure (an
    # unlabeled CEX/bridge/bundler wallet) and never clusters them. 0 (the
    # default) DISABLES it: the spread is derived from attacker-writable
    # feedback, so a farm could whitewash its own funder into a "hub" by
    # having a few funded wallets review sock agents. Labeled hubs (the
    # vendored eth-labels set) are always excluded regardless.
    sybil_hub_min_agents: int = 0

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
