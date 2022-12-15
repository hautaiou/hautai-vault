import logging
import random
import os
from pathlib import Path

import pydantic
import pytest

from ..hautai_vault.settings import VaultSettings, vault_settings_source


def test_settings_disabled():
    settings_1 = VaultSettings(enabled=False)
    os.environ["VAULT_ENABLED"] = random.choice(("0", "off", "f", "false", "n", "no"))
    settings_2 = VaultSettings()
    del os.environ["VAULT_ENABLED"]

    assert settings_1.enabled is settings_2.enabled is False
    assert settings_1.addr == settings_2.addr == "https://vault.infra.haut.ai"
    assert all(
        map(
            lambda f1, f2: f1 is f2 is None,
            (
                settings_1.env,
                settings_1.user_login,
                settings_1.jwt,
                settings_1.secrets_engine,
                settings_1.auth_role,
                settings_1.auth_path,
            ),
            (
                settings_2.env,
                settings_2.user_login,
                settings_2.jwt,
                settings_2.secrets_engine,
                settings_2.auth_role,
                settings_2.auth_path,
            ),
        )
    )
    assert isinstance(settings_1.token, pydantic.SecretStr)
    assert settings_1.token == settings_2.token
    assert settings_1.token_file == settings_2.token_file == ".vault-token"
    assert settings_1.secrets == settings_2.secrets == {"general": None}
    assert settings_1.logging_level == settings_2.logging_level == logging.DEBUG


def test_settings_invalid():
    with pytest.raises(ValueError):
        VaultSettings()


def test_settings_valid():
    prefix = "test"
    settings_1 = VaultSettings(env=prefix)
    os.environ["VAULT_ENV"] = prefix
    settings_2 = VaultSettings()
    del os.environ["VAULT_ENV"]

    settings_3 = VaultSettings(secrets_engine=prefix)
    os.environ["VAULT_SECRETS_ENGINE"] = prefix
    settings_4 = VaultSettings()
    del os.environ["VAULT_SECRETS_ENGINE"]

    assert settings_1.env is not None and settings_1.env == settings_2.env
    assert (
        settings_3.secrets_engine is not None
        and settings_3.secrets_engine == settings_4.secrets_engine
    )
    assert (
        settings_1.secrets
        == settings_2.secrets
        == settings_3.secrets
        == settings_4.secrets
        == {"general": f"{prefix}/data/general"}
    )
    assert all(
        map(
            lambda s: s.auth_role is s.auth_path is None,
            (settings_1, settings_2, settings_3, settings_4),
        )
    )


def test_settings_auth(vault_token_path: Path):
    prefix = "test"
    user_login = "test_user"
    token_file = "no-such-file"

    settings_1 = VaultSettings(env=prefix, user_login=user_login, token_file=token_file)
    os.environ["VAULT_USER_LOGIN"] = user_login
    settings_2 = VaultSettings(env=prefix, token_file=token_file)
    del os.environ["VAULT_USER_LOGIN"]
    os.environ["SERVICE_ACCOUNT_NAME"] = user_login
    settings_3 = VaultSettings(env=prefix, token_file=token_file)
    del os.environ["SERVICE_ACCOUNT_NAME"]

    auth_role = f"{prefix}-{user_login}"
    settings_4 = VaultSettings(env=prefix, auth_role=auth_role, token_file=token_file)

    assert (
        settings_1.auth_role
        == settings_2.auth_role
        == settings_3.auth_role
        == settings_4.auth_role
        == auth_role
    )

    with pytest.raises(ValueError):
        VaultSettings(auth_role=auth_role)
    with pytest.raises(ValueError):
        VaultSettings(token_file=token_file, auth_role=auth_role)
    with pytest.raises(ValueError):
        VaultSettings(token_file=token_file, secrets_engine=prefix, auth_role=auth_role)
    with pytest.raises(ValueError):
        VaultSettings(env=prefix, token_file=token_file)

    token = vault_token_path.read_text()
    auth_path = "test_auth_path"
    settings_5 = VaultSettings(token=token, secrets_engine=prefix, auth_path=auth_path)
    settings_6 = VaultSettings(token=token, env=prefix)

    assert (
        settings_5.auth_role is settings_6.auth_role is None
        and settings_5.token.get_secret_value()
        == settings_6.token.get_secret_value()
        == token
    )
    assert settings_5.auth_path == auth_path
    assert settings_6.auth_path is None

    settings_7 = VaultSettings(env=prefix, token_file=token_file, auth_role=auth_role)
    assert settings_7.auth_path == f"{prefix}_k8s"
