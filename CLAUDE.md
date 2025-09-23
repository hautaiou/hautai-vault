# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `hautai_vault`, a Python library that provides a unified interface for interacting with HashiCorp Vault. It's designed as an internal library for backend services and handles authentication and secret retrieval from Vault.

## Development Commands

### Installation and Setup
```bash
# Install all dependencies including dev tools
poetry install

# Install only production dependencies
poetry install --exclude dev
```

### Code Quality and Testing
```bash
# Format and lint code
make format          # Format code with ruff
make lint           # Check code with ruff (must be 0 warnings for CI)

# Run tests
make run_tests      # Run pytest with verbose output
pytest -svvv --log-cli-level=DEBUG tests/

# Pre-push validation
make pre_push_test  # Runs format, lint, tests, and security analysis
```

### Build and Publishing
```bash
# Build wheel package
make build_wheel    # Uses poetry build

# Publish to repository (CI use)
make push_wheel_to_repo
```

## Architecture

The library provides a settings integration for Pydantic that automatically retrieves secrets from HashiCorp Vault. Key architectural components:

### Authentication Methods
- **JWT Authentication** (`JWTAuthMethod`): Uses JWT tokens for authentication
- **Azure Authentication** (`AzureAuthMethod`): Uses Azure CLI access tokens via `az account get-access-token`
- **Kubernetes Authentication** (`K8sAuthMethod`): Uses Kubernetes service account tokens
- **Token Authentication**: Default method using VAULT_TOKEN env var or ~/.vault-token

### Core Classes
- `VaultBaseSettings`: Base class for settings that integrate with Vault. Subclasses must specify a `secret_path` class variable
- `VaultSettingsSource`: Custom Pydantic settings source that retrieves values from Vault KV v2 engine
- `AbstractVaultAuthMethod`: Base class for implementing custom authentication methods

### Usage Pattern
```python
class Settings(VaultBaseSettings, secret_path="sasuke/backend/service-name"):
    API_KEY: str
    DATABASE_URL: str

settings = Settings()  # Automatically retrieves secrets from Vault
```

## Configuration

- Uses Poetry for dependency management
- Ruff for linting and formatting (line length: 120)
- MyPy for type checking with Pydantic plugin
- Default Vault URL: `https://vault.infra.haut.ai`
- Default mount point: `dev`

## Environment Variables

Key environment variables for Vault configuration:
- `VAULT_ENABLED`: Enable/disable Vault integration (default: True)
- `VAULT_URL`: Vault server URL
- `VAULT_AUTH_METHOD`: Authentication method (jwt/azure/k8s)
- `VAULT_AUTH_ROLE`: Role name for authentication
- `VAULT_MOUNT_POINT`: KV mount point

Authentication-specific variables:
- JWT: `VAULT_AUTH_JWT_TOKEN`, `VAULT_AUTH_JWT_PATH`
- Azure: `VAULT_AUTH_AZURE_MOUNT_POINT`
- K8s: `VAULT_AUTH_K8S_TOKEN_PATH`, `VAULT_AUTH_K8S_MOUNT_POINT`

## Testing

Currently has minimal test coverage. The main test file (`tests/test_vault.py`) contains only a placeholder test questioning how to test Vault client integration in CI.