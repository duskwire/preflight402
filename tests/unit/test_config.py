import re
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from preflight402.config import Settings, get_settings

# PREFLIGHT402_* env vars and any real .env are scrubbed session-wide in
# tests/conftest.py (also protecting collection-time imports of the app).

REPO_ROOT = Path(__file__).parents[2]
ENV_EXAMPLE = REPO_ROOT / ".env.example"


def test_defaults_boot_without_any_env() -> None:
    settings = Settings(_env_file=None)
    assert settings.environment == "dev"
    assert settings.db_path == Path("preflight402.db")
    assert settings.alchemy_api_key is None
    assert settings.helius_api_key is None
    assert settings.probe_timeout_s == 10.0
    assert settings.probe_concurrency == 20
    assert settings.per_host_min_interval_s == 60.0
    assert settings.scheduler_cycle_s == 900.0
    assert settings.preflight_cache_ttl_s == 300.0


def test_env_example_parses_and_matches_defaults() -> None:
    # Task 0.3 acceptance: the app boots with .env.example. The example file
    # documents the defaults, so loading it must produce exactly the same
    # settings as no file at all — drift in either direction fails here.
    assert ENV_EXAMPLE.is_file()
    assert Settings(_env_file=ENV_EXAMPLE) == Settings(_env_file=None)


def test_env_example_documents_every_field() -> None:
    # Set equality, not substring: catches stale/renamed .env.example entries
    # (which extra="ignore" would otherwise swallow silently) as well as
    # missing ones.
    documented = set(
        re.findall(r"^#? ?(PREFLIGHT402_[A-Z0-9_]+)=", ENV_EXAMPLE.read_text(), re.MULTILINE)
    )
    expected = {f"PREFLIGHT402_{name.upper()}" for name in Settings.model_fields}
    assert documented == expected


def test_empty_env_values_mean_unset(monkeypatch) -> None:
    # "VAR=" (set but blank, common in CI yaml and copied .env files) must
    # behave like unset — not SecretStr('') / Path('.').
    monkeypatch.setenv("PREFLIGHT402_ALCHEMY_API_KEY", "")
    monkeypatch.setenv("PREFLIGHT402_DB_PATH", "")
    settings = Settings(_env_file=None)
    assert settings.alchemy_api_key is None
    assert settings.db_path == Path("preflight402.db")


def test_dotenv_file_loaded_from_cwd(monkeypatch, tmp_path: Path) -> None:
    # The documented deploy workflow: a .env in the working directory, no
    # explicit _env_file. Guards the env_file entry in model_config.
    (tmp_path / ".env").write_text("PREFLIGHT402_PROBE_CONCURRENCY=99\n")
    monkeypatch.chdir(tmp_path)
    assert Settings().probe_concurrency == 99


def test_env_vars_override_defaults(monkeypatch) -> None:
    monkeypatch.setenv("PREFLIGHT402_ENVIRONMENT", "prod")
    monkeypatch.setenv("PREFLIGHT402_DB_PATH", "/tmp/other.db")
    monkeypatch.setenv("PREFLIGHT402_PROBE_TIMEOUT_S", "2.5")
    monkeypatch.setenv("PREFLIGHT402_ALCHEMY_API_KEY", "sekrit")
    settings = Settings(_env_file=None)
    assert settings.environment == "prod"
    assert settings.db_path == Path("/tmp/other.db")
    assert settings.probe_timeout_s == 2.5
    assert settings.alchemy_api_key == SecretStr("sekrit")


def test_secrets_do_not_leak_in_repr(monkeypatch) -> None:
    monkeypatch.setenv("PREFLIGHT402_ALCHEMY_API_KEY", "sekrit")
    settings = Settings(_env_file=None)
    for rendered in (repr(settings), str(settings), repr(settings.alchemy_api_key)):
        assert "sekrit" not in rendered
    assert settings.alchemy_api_key.get_secret_value() == "sekrit"


def test_invalid_values_rejected(monkeypatch) -> None:
    monkeypatch.setenv("PREFLIGHT402_ENVIRONMENT", "staging")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
    monkeypatch.delenv("PREFLIGHT402_ENVIRONMENT")
    monkeypatch.setenv("PREFLIGHT402_PROBE_CONCURRENCY", "twenty")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_get_settings_is_cached() -> None:
    get_settings.cache_clear()
    try:
        assert get_settings() is get_settings()
    finally:
        get_settings.cache_clear()
