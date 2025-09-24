# AGENTS

Guidance for AI coding agents working in this repository. Keep this file the source of truth when assisting developers so that all tools share the same mental model of the project.

## Repository Snapshot
- `hautai_vault/__init__.py`: the full implementation of the Vault client integration (authentication flows, settings source, helper utilities).
- `tests/`: pytest suite validating Vault settings behaviour with stubbed hvac clients (`tests/test_vault.py`).
- `pyproject.toml`: project metadata for uv/hatch build, dependency groups, Ruff, MyPy.
- `Makefile`: convenience targets for formatting, linting, testing, packaging, and publishing.
- `README.md`: legacy placeholder from the original GitLab template (do not rely on it for accurate instructions).

## Environment & Tooling
- Supported Python: `>=3.9,<4` (declared in `pyproject.toml`).
- Dependency management: uv (`uv sync` defaults to installing the `dev` group).
- Linting & formatting: Ruff (`ruff check`, `ruff format`), line length 120.
- Static typing: MyPy with the Pydantic plugin.
- Test framework: Pytest (with pytest-cov and pytest-xdist available).

### Installation
- `uv sync` – install runtime dependencies alongside the `dev` group.
- `uv sync --no-group dev` – install runtime dependencies only.
- Private Azure DevOps feeds are marked `explicit=true`; include them only when needed (e.g. `uv sync --index haut_ai`). Configure credentials beforehand or the request will 401.

### Quality Commands (Makefile)
- `make format` → `uv run ruff check --fix` then `uv run ruff format`.
- `make lint` → `uv run ruff check --fix` (CI expects zero lint warnings).
- `make run_tests` → `uv run pytest -svvv --log-cli-level=DEBUG tests/`.
- `make pre_push_test` → runs format, lint, tests, and security analysis (placeholder target `analyse_security`).

### Packaging
- `make build_wheel` → `uv build --wheel --sdist`.
- `make push_wheel_to_repo` → builds then calls `uv publish` against the Azure DevOps feed (set credentials first).

## Core Library Architecture
- **`VaultBaseSettings`**: Base class that injects `VaultSettingsSource` into Pydantic’s settings pipeline. Subclasses must provide `secret_path` via class definition (`class Settings(VaultBaseSettings, secret_path="my/path"):`).
- **`VaultSettingsSource`**: Custom Pydantic source that reads secrets from a KV v2 engine. Evaluation order: environment → `.env` → init kwargs → Vault → file secrets.
- **`VaultSettings`**: Global configuration read once (cached) from environment; controls whether Vault is enabled, URL, auth method, and mount point.
- **`register_vault_auth_method`**: Extension hook for registering new authentication strategies beyond the built-ins.

### Authentication Strategies
- `jwt` (`JWTAuthMethod`): expects `VAULT_AUTH_JWT_TOKEN`, optional `VAULT_AUTH_JWT_PATH`.
- `azure` (`AzureAuthMethod`): shells out to `az account get-access-token`; mount point defaults to `azure`.
- `k8s` (`K8sAuthMethod`): reads a service account token from `VAULT_AUTH_K8S_TOKEN_PATH`, authenticates against the configured mount point.
- Token auth fallback: if `VAULT_AUTH_METHOD` unset, `hvac.Client` relies on `VAULT_TOKEN` or `~/.vault-token`.

### Default Configuration
- Vault URL: `https://vault.infra.haut.ai`.
- Default KV mount: `dev`.
- Global toggle: `VAULT_ENABLED` (defaults to `True`).

### Example Usage
```python
from hautai_vault import VaultBaseSettings

class Settings(VaultBaseSettings, secret_path="sasuke/backend/service-name"):
    API_KEY: str
    DATABASE_URL: str

settings = Settings()
```
The first instantiation pulls secrets from Vault unless disabled or overridden by environment/init values.

## Testing Notes
- Tests mock external Vault access by monkeypatching `hautai_vault.Client` with dummy hvac clients; never attempt live Vault calls in CI.
- Run locally via `uv run pytest --cov=hautai_vault --cov-report=term-missing` after installing dependencies.
- Prefer fast unit tests; integration tests should be gated or skipped by default.

## When Making Changes
- Follow Ruff auto-fixes, then re-run `make lint` to ensure a clean state.
- Update or add tests alongside behavioural changes.
- Document new environment variables or auth flows here and in `README.md` (when that file is modernised).
- Avoid committing secrets; rely on Vault for runtime secrets.

## Troubleshooting
- Azure auth requires the Azure CLI to be logged in (`az login`).
- Kubernetes auth expects the service account token file to exist; otherwise the code raises a descriptive `ValueError`.
- If `VAULT_ENABLED=0`, the settings source returns an empty dict and only env/init values are used.

Keep this file current whenever the project structure, tooling, or auth flows change so every agent starts from an accurate briefing.
