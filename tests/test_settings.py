import logging
import random
import os
import typing as ty

import pytest

from ..hautai_vault.settings import VaultSettings

if ty.TYPE_CHECKING:
    from pathlib import Path


def test_not_configured():
    message = (
        "Could not construct proper paths to Vault secrets: "
        "neither `secrets_engine` nor `env` fields are set."
    )
    with pytest.raises(ValueError, match=message):
        VaultSettings()


def test_disabled():
    settings_1 = VaultSettings(enabled=False)

    os.environ["VAULT_ENABLED"] = random.choice(("0", "off", "f", "false", "n", "no"))
    settings_2 = VaultSettings()
    del os.environ["VAULT_ENABLED"]

    assert settings_1.enabled is settings_2.enabled is False
    assert settings_1.addr == settings_2.addr == "https://vault.infra.haut.ai"
    assert settings_1.token_path == settings_2.token_path == "~/.vault-token"
    assert all(
        map(
            lambda f1, f2: f1 is f2 is None,
            (
                settings_1.token,
                settings_1.msi_token,
                settings_1.jwt,
                settings_1.env,
                settings_1.user_login,
                settings_1.auth_role,
                settings_1.auth_path,
                settings_1.secrets_engine,
            ),
            (
                settings_2.token,
                settings_2.msi_token,
                settings_2.jwt,
                settings_2.env,
                settings_2.user_login,
                settings_2.auth_role,
                settings_2.auth_path,
                settings_2.secrets_engine,
            ),
        )
    )
    assert settings_1.secrets == settings_2.secrets == {"general": None}
    assert settings_1.logging_level == settings_2.logging_level == logging.INFO


def test_token(invalid_token_path: None, token_tmp_path: "Path"):
    token = token_tmp_path.read_text()
    env = "test"

    settings_1 = VaultSettings(token=token, env=env)
    settings_2 = VaultSettings(token_path=token_tmp_path.as_posix(), env=env)

    assert (
        settings_1.token.get_secret_value()
        == settings_2.token.get_secret_value()
        == token
    )


def test_auth_role(invalid_token_path: None):
    env = "test"
    user_login = "test_user"
    auth_role = f"{env}-{user_login}"

    settings_1 = VaultSettings(env=env, user_login=user_login)

    os.environ["VAULT_USER_LOGIN"] = user_login
    settings_2 = VaultSettings(env=env)
    del os.environ["VAULT_USER_LOGIN"]

    os.environ["SERVICE_ACCOUNT_NAME"] = user_login
    settings_3 = VaultSettings(env=env)
    del os.environ["SERVICE_ACCOUNT_NAME"]

    settings_4 = VaultSettings(env=env, auth_role=auth_role)

    assert (
        settings_1.auth_role
        == settings_2.auth_role
        == settings_3.auth_role
        == settings_4.auth_role
        == auth_role
    )

    message = (
        "Improperly configured settings: "
        "either `auth_role` or both `env` and `user_login` fields "
        "should be set to authenticate the Vault client in production."
    )
    with pytest.raises(ValueError, match=message):
        VaultSettings(env=env)


def test_auth_path(invalid_token_path: None, token_tmp_path: "Path"):
    token = token_tmp_path.read_text()
    env = "test"
    user_login = "test_user"
    auth_role = f"{env}-{user_login}"
    auth_path = "test_auth_path"

    settings_1 = VaultSettings(env=env, auth_role=auth_role, auth_path=auth_path)
    settings_2 = VaultSettings(env=env, user_login=user_login)
    settings_3 = VaultSettings(token=token, env=env)

    assert settings_1.auth_path == auth_path
    assert settings_2.auth_path == f"{env}_k8s"
    assert settings_3.auth_path is None

    message = (
        "Improperly configured settings: "
        "either `auth_path` or `env` fields "
        "should be set to authenticate the Vault client in production."
    )
    with pytest.raises(ValueError, match=message):
        VaultSettings(auth_role=auth_role)


def test_secrets(invalid_token_path: str, token_tmp_path: "Path"):
    token = token_tmp_path.read_text()
    secrets_engine = env = "test"

    settings_1 = VaultSettings(token=token, secrets_engine=secrets_engine)

    os.environ["VAULT_SECRETS_ENGINE"] = secrets_engine
    settings_2 = VaultSettings(token=token)
    del os.environ["VAULT_SECRETS_ENGINE"]

    settings_3 = VaultSettings(token=token, env=env)

    os.environ["VAULT_ENV"] = env
    settings_4 = VaultSettings(token=token)
    del os.environ["VAULT_ENV"]

    assert (
        settings_1.secrets_engine is not None
        and settings_1.secrets_engine == settings_2.secrets_engine
    )
    assert (
        settings_1.secrets
        == settings_2.secrets
        == settings_3.secrets
        == settings_4.secrets
        == {"general": f"{env}/data/general"}
    )

    message = (
        "Could not construct proper paths to Vault secrets: "
        "neither `secrets_engine` nor `env` fields are set."
    )
    with pytest.raises(ValueError, match=message):
        VaultSettings(token=token)
