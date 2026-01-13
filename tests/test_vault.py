from __future__ import annotations

import os
import sys
import typing as ty
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import pytest

try:
    import pydantic  # noqa: F401
    import pydantic_settings  # noqa: F401
    import requests  # noqa: F401
except ModuleNotFoundError as exc:  # pragma: no cover - guard for local dev
    pytest.skip(f"runtime dependency missing: {exc.name}", allow_module_level=True)

if "hvac" not in sys.modules:
    hvac_stub = ModuleType("hvac")

    class _UnconfiguredClient:  # pragma: no cover - should be overridden in tests
        def __init__(self, *_, **__):
            raise AssertionError("tests must monkeypatch hautai_vault.Client before use")

    hvac_stub.Client = _UnconfiguredClient
    sys.modules["hvac"] = hvac_stub

import hautai_vault


class DummyKVReader:
    def __init__(self, data: dict[str, str]) -> None:
        self._data = data

    def read_secret_version(self, *_, **__) -> dict[str, dict[str, dict[str, str]]]:
        return {"data": {"data": self._data}}


class DummyClient:
    def __init__(self, secret_data: dict[str, str]) -> None:
        self.secrets = SimpleNamespace(kv=SimpleNamespace(v2=DummyKVReader(secret_data)))


@pytest.fixture(autouse=True)
def _reset_vault_settings() -> None:
    # Clear environment variables
    for var in ["VAULT_ENABLED", "VAULT_AUTH_METHOD", "VAULT_URL", "VAULT_MOUNT_POINT"]:
        os.environ.pop(var, None)


@patch.dict(os.environ, {"VAULT_ENABLED": "1", "VAULT_URL": "http://vault.example"})
@patch("hautai_vault.Client")
def test_vault_settings_source_reads_secret(mock_client) -> None:
    secret_data = {"API_KEY": "from-vault"}
    mock_client.return_value = DummyClient(secret_data)

    class Settings(hautai_vault.VaultBaseSettings, secret_path="example/path"):
        API_KEY: str

    settings = Settings()

    assert settings.API_KEY == "from-vault"


@patch.dict(os.environ, {"VAULT_ENABLED": "1", "VAULT_AUTH_METHOD": "nonexistent", "VAULT_URL": "http://vault.example"})
def test_unsupported_auth_method_raises() -> None:
    class Settings(hautai_vault.VaultBaseSettings, secret_path="example/path"):
        API_KEY: str

    with pytest.raises(ValueError, match="Vault auth method `nonexistent` is not supported"):
        Settings()


@patch.dict(os.environ, {"VAULT_ENABLED": "1", "VAULT_AUTH_METHOD": "dummy", "VAULT_URL": "http://vault.example"})
def test_custom_auth_method_used() -> None:
    secret_data = {"API_KEY": "from-custom-auth"}
    dummy_client = DummyClient(secret_data)

    class DummyAuth(hautai_vault.AbstractVaultAuthMethod):
        role: str = "role"
        called: ty.ClassVar[int] = 0

        def get_authorized_client(self) -> hautai_vault.Client:
            type(self).called += 1
            return dummy_client

    with patch.object(hautai_vault, "_VAULT_AUTH_METHODS", {"dummy": DummyAuth}):

        class Settings(hautai_vault.VaultBaseSettings, secret_path="example/path"):
            API_KEY: str

        settings = Settings()

    assert DummyAuth.called == 1
    assert settings.API_KEY == "from-custom-auth"


def test_ps_access_token_legacy_attribute_access() -> None:
    token_payload = {
        "accessToken": "token-value",
        "expiresOn": "2024-12-31T23:59:59Z",
        "subscription": "sub",
        "tenant": "tenant",
        "tokenType": "Bearer",
    }

    token = hautai_vault.PSAccessToken.model_validate(token_payload)

    assert token.access_token == "token-value"
    assert token.accessToken == "token-value"
    assert token.token_type == "Bearer"
    assert token.tokenType == "Bearer"


@pytest.mark.parametrize(
    "payload",
    [
        {"vault_url": "http://vault.example"},
        {"VAULT_URL": "http://vault.example"},
        {"vault_addr": "http://vault.example"},
        {"VAULT_ADDR": "http://vault.example"},
    ],
)
def test_vault_settings_url_aliases(payload: dict[str, str]) -> None:
    settings = hautai_vault.VaultSettings.model_validate(payload)

    assert settings.url == "http://vault.example"
