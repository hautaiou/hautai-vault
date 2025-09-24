# HautAI Vault

A Python helper library that standardises how backend services at Haut.AI authenticate against and read secrets from HashiCorp Vault.

## Features
- **Drop-in settings base**: Inherit from `VaultBaseSettings` to fetch secrets from a Vault KV v2 engine while keeping Pydantic ergonomics.
- **Multiple auth flows**: Built-in Azure CLI, JWT, and Kubernetes service account authentication with a fallback to `VAULT_TOKEN`.
- **Configurable behaviour**: Toggle Vault usage via environment variables; override values using standard Pydantic mechanisms.
- **Extension friendly**: Register custom authentication methods with `register_vault_auth_method`.

## Installation
```bash
poetry install            # full environment (dev + tests)
poetry install --group dev  # runtime + dev tooling
poetry install --without dev tests  # production-only install
```
> Tip: The legacy `make install_requirements` target is broken; use Poetry commands directly.

## Usage
```python
from hautai_vault import VaultBaseSettings

class Settings(VaultBaseSettings, secret_path="sasuke/backend/service-name"):
    API_KEY: str
    DATABASE_URL: str

settings = Settings()
print(settings.API_KEY)
```
Vault is enabled by default and will contact `https://vault.infra.haut.ai` using the configured authentication method. Values passed via environment variables or constructor arguments override secrets returned from Vault.

### Environment Variables
- `VAULT_ENABLED` (default `true`)
- `VAULT_URL` (default `https://vault.infra.haut.ai`)
- `VAULT_AUTH_METHOD` (`jwt`, `azure`, `k8s` or unset for token auth)
- `VAULT_AUTH_ROLE`
- `VAULT_MOUNT_POINT` (default `dev`)

#### Auth-specific variables
- **JWT**: `VAULT_AUTH_JWT_TOKEN`, optional `VAULT_AUTH_JWT_PATH`
- **Azure**: `VAULT_AUTH_AZURE_MOUNT_POINT` (defaults to `azure`)
- **Kubernetes**: `VAULT_AUTH_K8S_TOKEN_PATH`, `VAULT_AUTH_K8S_MOUNT_POINT`

## Development Workflow
All commands below are defined in the `Makefile` unless stated otherwise.

```bash
make format         # ruff check --fix && ruff format
make lint           # ruff check --fix (CI expects zero warnings)
make run_tests      # pytest -svvv --log-cli-level=DEBUG tests/
make pre_push_test  # format + lint + tests + security placeholder
```

Additional tooling:
- Ruff line length: 120
- MyPy plugin: `pydantic.mypy`

## Packaging & Publishing
```bash
make build_wheel         # poetry build --skip-existing
make push_wheel_to_repo  # poetry publish --build --skip-existing -r haut_ai_publish -vvv --no-interaction
```
Publishing requires access to the Azure DevOps `haut_ai_publish` feed.

## Testing Strategy
Test coverage is currently minimal (`tests/test_vault.py`). When adding tests, mock Vault interactions; CI does not provide a live Vault instance. Prefer fast unit tests and guard any integration tests with explicit markers.

## Contributing
1. Ensure new functionality includes adequate tests.
2. Run `make format` and `make lint` to keep Ruff happy.
3. Update documentation (`README.md`, `AGENTS.md`) when behaviour or configuration changes.
4. Never commit real secrets—Vault handles runtime credentials.

## Troubleshooting
- Azure auth requires the Azure CLI to be logged in (`az login`).
- Kubernetes auth expects the service account token file at `VAULT_AUTH_K8S_TOKEN_PATH`; otherwise the client raises a `ValueError`.
- Set `VAULT_ENABLED=0` locally to bypass Vault and rely purely on environment/constructor values.

## License
Internal use only. Contact the Haut.AI platform team before sharing outside the organisation.
