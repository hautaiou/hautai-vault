from __future__ import annotations

from types import ModuleType, SimpleNamespace
import typing as ty

import sys

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
def _reset_vault_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VAULT_ENABLED", raising=False)
    monkeypatch.delenv("VAULT_AUTH_METHOD", raising=False)
    monkeypatch.delenv("VAULT_URL", raising=False)
    monkeypatch.delenv("VAULT_MOUNT_POINT", raising=False)
    monkeypatch.setattr(hautai_vault, "_vault_settings", None, raising=False)


def test_vault_settings_source_reads_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    secret_data = {"API_KEY": "from-vault"}

    def _fake_client(url: str, session: object) -> DummyClient:  # noqa: ARG001
        return DummyClient(secret_data)

    monkeypatch.setenv("VAULT_ENABLED", "1")
    monkeypatch.setattr(hautai_vault, "Client", _fake_client)

    class Settings(hautai_vault.VaultBaseSettings, secret_path="example/path"):
        API_KEY: str

    settings = Settings()

    assert settings.API_KEY == "from-vault"


def test_vault_disabled_skips_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ENABLED", "0")
    monkeypatch.setenv("API_KEY", "from-env")

    def _should_not_run(*args, **kwargs):  # noqa: ARG001
        raise AssertionError("Vault client must not be constructed when VAULT_ENABLED=0")

    monkeypatch.setattr(hautai_vault, "Client", _should_not_run)

    class Settings(hautai_vault.VaultBaseSettings, secret_path="example/path"):
        API_KEY: str

    settings = Settings()

    assert settings.API_KEY == "from-env"


def test_unsupported_auth_method_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ENABLED", "1")
    monkeypatch.setenv("VAULT_AUTH_METHOD", "nonexistent")

    class Settings(hautai_vault.VaultBaseSettings, secret_path="example/path"):
        API_KEY: str

    with pytest.raises(ValueError, match="Vault auth method `nonexistent` is not supported"):
        Settings()


def test_custom_auth_method_used(monkeypatch: pytest.MonkeyPatch) -> None:
    secret_data = {"API_KEY": "from-custom-auth"}
    dummy_client = DummyClient(secret_data)

    class DummyAuth(hautai_vault.AbstractVaultAuthMethod):
        role: str = "role"
        called: ty.ClassVar[int] = 0

        def get_authorized_client(self) -> hautai_vault.Client:
            type(self).called += 1
            return dummy_client

    monkeypatch.setenv("VAULT_ENABLED", "1")
    monkeypatch.setenv("VAULT_AUTH_METHOD", "dummy")
    monkeypatch.setattr(hautai_vault, "_VAULT_AUTH_METHODS", {"dummy": DummyAuth})

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
