"""Vault settings."""

__all__ = ("VaultSettings", "vault_settings_source")

import logging
import typing as ty

import pydantic

from .client import VaultClient
from .commands import GetVaultSecrets
from .logger import logger
from .utils import read_auth_token_from_file

DictStrAny = dict[str, ty.Any]


class VaultSettings(pydantic.BaseSettings):
    """Provides the nessesary means to set up and use Hashicorp Vault.

    DictStrAny:
        enabled -- flag to activate the Vault setup (default: {`True`})

        addr -- URL for the Vault instance being addressed
            (default: {"https://vault.infra.haut.ai"})

        token_path -- either relative or absolute path to a file from which a
            client auth token should be read (default: {"~/.vault-token"})

        token -- client token for bypassing auth methods (default: {`None`})

        msi_token -- MSI token for Azure auth method (default: {`None`})

        jwt -- JSON Web Token for JWT auth method (default: {`None`})

        env -- active environment for backend services (default: {`None`})

        user_login -- used in conjunction with `self.env` to form a Vault Role
            for backend services, e.g. "dev-saas-core" (default: {`None`})

        auth_role -- Vault Role to authenticate against (default: {`None`})

        auth_path -- auth login method path (default: {`None`})

        secrets_engine -- KV storage backend (default: {`None`})

        secrets -- mapping of aliases to secrets' paths. When specifying a
            path, omit the "`self.secrets_engine`/data/" part, as it will be
            prepended automatically during the initialisation process.
            Alternatively, set `None` as a mapping value for aliases which
            match their secrets' paths. (default: {"general": `None`})

        logging_level -- severity level of logging (default: {`logging.INFO`})
    """

    enabled: bool = True
    addr: str = "https://vault.infra.haut.ai"

    token_path: str = "~/.vault-token"
    token: ty.Optional[pydantic.SecretStr] = None
    msi_token: ty.Optional[pydantic.SecretStr] = None
    azure: bool = False
    jwt: ty.Optional[pydantic.SecretStr] = None

    env: ty.Optional[str] = None
    user_login: ty.Optional[str] = pydantic.Field(
        None,
        env=["vault_user_login", "service_account_name"],
    )

    auth_role: ty.Optional[str] = None
    auth_path: ty.Optional[str] = None

    secrets_engine: ty.Optional[str] = None
    secrets: dict[str, ty.Optional[str]] = {"general": None}

    logging_level: int = logging.INFO

    def __init__(self, **kwargs) -> None:
        """Instantiate VaultSettings, set up logging and secrets."""
        super().__init__(**kwargs)

        logging.basicConfig()
        logging.getLogger(logger.name).setLevel(self.logging_level)

        if self.enabled:
            self._set_secrets_paths()

    def _set_secrets_paths(self) -> None:
        prefix = self.secrets_engine or self.env
        if prefix is None:
            raise ValueError(
                "Could not construct proper paths to Vault secrets: "
                "neither `secrets_engine` nor `env` fields are set."
            )
        for key, value in self.secrets.items():
            path = key if value is None else value
            self.secrets[key] = f"{prefix}/data/{path.strip('/')}"

    @staticmethod
    def _is_allowed(value: ty.Optional[str], values: DictStrAny) -> bool:
        return (
            value is not None
            or values["enabled"] is False
            or values.get("token") is not None
        )

    @pydantic.validator("token", always=True)
    def _set_token(
        cls,
        value: ty.Optional[pydantic.SecretStr],
        values: DictStrAny,
    ) -> ty.Optional[pydantic.SecretStr]:
        if cls._is_allowed(value, values):
            return value
        return read_auth_token_from_file(values["token_path"])

    @pydantic.validator("auth_role", always=True)
    def _check_auth_role(
        cls,
        value: ty.Optional[str],
        values: DictStrAny,
    ) -> ty.Optional[str]:
        if cls._is_allowed(value, values):
            return value

        env = values.get("env")
        user_login = values.get("user_login")
        if env is not None and user_login is not None:
            return f"{env}-{user_login}"

        raise ValueError(
            "Improperly configured settings: "
            "either `auth_role` or both `env` and `user_login` fields "
            "should be set to authenticate the Vault client in production."
        )

    @pydantic.validator("auth_path", always=True)
    def _check_auth_path(
        cls,
        value: ty.Optional[str],
        values: DictStrAny,
    ) -> ty.Optional[str]:
        if cls._is_allowed(value, values):
            return value

        env = values.get("env")
        if env is not None:
            return f"{env}_k8s"

        raise ValueError(
            "Improperly configured settings: "
            "either `auth_path` or `env` fields "
            "should be set to authenticate the Vault client in production."
        )

    class Config:
        env_file: str = ".env"
        env_prefix: str = "vault_"


# For static type checking.
class ConfigWithVaultSettings(pydantic.BaseConfig):
    vault_settings: ty.ClassVar[VaultSettings]


def vault_settings_source(settings: pydantic.BaseSettings) -> DictStrAny:
    """Use Vault as a source for setting up an application.

    Arguments:
        settings -- application settings

    Raises:
        TypeError -- `Config.vault_settings` is not a `VaultSettings` instance

    Returns:
        a dictionary of fields which values are set via Vault.
    """
    if not hasattr(settings.__config__, "vault_settings"):
        logger.debug(
            "`Config.vault_settings` field is not provided. "
            "Ignoring the fields setup via Vault..."
        )
        return {}

    config: type[ConfigWithVaultSettings] = settings.__config__
    if not isinstance(config.vault_settings, VaultSettings):
        raise TypeError("`Config.vault_settings` is not a `VaultSettings` instance")

    client = _get_client(config.vault_settings)
    return GetVaultSecrets(settings=settings, client=client).execute()


def _get_client(vault_settings: VaultSettings) -> VaultClient:
    auth_token = vault_settings.token
    if auth_token is not None:
        return VaultClient(token=auth_token.get_secret_value(), url=vault_settings.addr)

    client = VaultClient(url=vault_settings.addr)
    client.auth(vault_settings)
    return client
