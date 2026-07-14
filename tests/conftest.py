"""Session-wide hermeticity for the test suite.

The scrub below runs at conftest import — before pytest imports any test
module, which is the moment preflight402.api.rest constructs Settings().
Without it, a developer's exported PREFLIGHT402_* variables or a broken .env
in the repo root would leak into (or abort) the whole suite at collection.
"""

import os
import tempfile

import pytest

# Case-insensitive: pydantic-settings matches env vars case-insensitively.
for _key in list(os.environ):
    if _key.upper().startswith("PREFLIGHT402_"):
        del os.environ[_key]


def pytest_configure(config: pytest.Config) -> None:
    # A fresh CWD so config's env_file=".env" never finds a developer's real
    # file. Runs after pytest resolves testpaths (a conftest-import-time chdir
    # would break that) but before any test module — and therefore the app —
    # is imported.
    os.chdir(tempfile.mkdtemp(prefix="preflight402-tests-"))


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep individual tests isolated from PREFLIGHT402_* vars set mid-session."""
    for key in list(os.environ):
        if key.upper().startswith("PREFLIGHT402_"):
            monkeypatch.delenv(key)


@pytest.fixture
def anyio_backend() -> str:
    """Async tests (@pytest.mark.anyio) run on asyncio only."""
    return "asyncio"
