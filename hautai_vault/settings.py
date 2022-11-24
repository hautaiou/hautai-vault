"""Vault settings."""

__all__ = ("VaultSettings", "vault_settings_source")

import enum
import logging
import sys
import typing as ty

import pydantic
from hvac.exceptions import VaultError
from pydantic.env_settings import SettingsError
from pydantic.fields import ModelField

from .client import VaultClient
from .logger import logger
from .utils import maybe_get_auth_token_from_homedir


class VaultSettings(pydantic.BaseSettings):
    """Provides the nessesary means to set up and use Hashicorp Vault.

    Fields:
        enabled -- can the Vault be used or not (default: {True})

        addr -- URL for the Vault instance being addressed (
            default: {"https://vault.infra.haut.ai"}
        )

        env -- current K8s env for backend services (default: {None})

        user_login -- used as a fallback auth role together with env (
            default: {None}
        )

        token -- Vault token for bypassing auth methods (default: {None})

        jwt -- JSON Web Token for JWT auth method (default: {None})

        secrets -- aliases to secrets' paths mapping (
            default: {"general": None}
        ). If None is assigned as an item's value instead of path to a secret,
        then an alias name will be used as a path.

        secrets_engine -- KV storage mount point (default: {None})

        auth_role -- Vault auth role (default: {None})

        auth_path -- auth login method path (default: {None})

        logging_level -- severity level of logging (default: {`logging.DEBUG`})
    """

    enabled: bool = True
    addr: str = "https://vault.infra.haut.ai"

    env: ty.Optional[str] = None
    user_login: ty.Optional[str] = pydantic.Field(
        None,
        env=["vault_user_login", "service_account_name"],
    )

    token: ty.Optional[pydantic.SecretStr] = None
    jwt: ty.Optional[pydantic.SecretStr] = None

    secrets: dict[str, ty.Optional[str]] = {"general": None}
    secrets_engine: ty.Optional[str] = None

    auth_role: ty.Optional[str] = None
    auth_path: ty.Optional[str] = None

    logging_level: int = logging.DEBUG

    def __init__(self, **kwargs) -> None:
        """Instantiate VaultSettings, set up logging and secrets."""
        super().__init__(**kwargs)

        logging.basicConfig()
        logging.getLogger(logger.name).setLevel(self.logging_level)

        self._set_secrets_paths()

    def _set_secrets_paths(self) -> None:
        for key, value in self.secrets.items():
            path = key if value is None else value
            self.secrets[key] = f"{self.secrets_engine}/data/{path.strip('/')}"

    @pydantic.validator("token", pre=True, always=True)
    def _set_token(
        cls, value: ty.Optional[pydantic.SecretStr]
    ) -> ty.Optional[pydantic.SecretStr]:
        if value is not None:
            logger.debug("Found Vault auth token in environment variables.")
            return value
        return maybe_get_auth_token_from_homedir()

    @pydantic.validator("secrets_engine", pre=True, always=True)
    def _set_secrets_engine(
        cls, value: ty.Optional[str], values: dict[str, ty.Any]
    ) -> ty.Optional[str]:
        if value is not None:
            return value.strip("/")
        if values["env"] is not None:
            return values["env"]
        return sys.exit(
            "Either VAULT_SECRETS_ENGINE or VAULT_ENV envs must be set "
            "for constructing proper paths to Vault secrets. "
        )

    @pydantic.validator("auth_role", pre=True, always=True)
    def _set_auth_role(
        cls, value: ty.Optional[str], values: dict[str, ty.Any]
    ) -> ty.Optional[str]:
        if value is not None:
            return value
        if values["token"] is not None:
            return None
        if values["env"] is not None and values["user_login"] is not None:
            return f"{values['env']}-{values['user_login']}"
        return sys.exit(
            "Either set VAULT_AUTH_ROLE or both VAULT_ENV and VAULT_USER_LOGIN envs "
            "to authenticate via K8s or JWT auth methods in production. "
            "For a local development, you could set VAULT_TOKEN env or "
            "login via Vault CLI prior to executing the script."
        )

    @pydantic.validator("auth_path", pre=True, always=True)
    def _set_auth_path(
        cls, value: ty.Optional[str], values: dict[str, ty.Any]
    ) -> ty.Optional[str]:
        if value is not None:
            return value.strip("/")
        if values["token"] is not None:
            return None
        if values["env"] is not None:
            return f"{values['env']}_k8s"
        return sys.exit(
            "Either VAULT_AUTH_PATH or VAULT_ENV envs must be set "
            "to authenticate via K8s or JWT auth methods in production. "
            "For a local development, you could set VAULT_TOKEN env or "
            "login via Vault CLI prior to executing the script."
        )

    class Config:
        env_file: str = ".env"
        env_prefix: str = "vault_"


JSONDict = dict[str, ty.Any]


def vault_settings_source(settings: pydantic.BaseSettings) -> JSONDict:
    """Enable Vault as a source for setting up an application.

    Arguments:
        settings -- application settings

    Returns:
        a dictionary of fields which values are set via Vault.
    """
    vault_settings: VaultSettings = settings.__config__.vault_settings
    client = _setup_client(vault_settings)
    return _setup_fields(settings, client)


def _setup_client(vault_settings: VaultSettings) -> VaultClient:
    auth_token = vault_settings.token
    if auth_token is not None:
        return VaultClient(token=auth_token.get_secret_value(), url=vault_settings.addr)
    client = VaultClient(url=vault_settings.addr)
    client.auth(vault_settings)
    return client


class FieldSecretsArg(str, enum.Enum):
    KEY = "key"
    PATH = "path"


def _setup_fields(settings: pydantic.BaseSettings, client: VaultClient) -> JSONDict:
    logger.info("Starting to fill in fields with Vault secrets' data...")
    vault_fields: JSONDict = {}

    for field in settings.__fields__.values():
        secret_path: ty.Optional[str] = _get_field_extra_arg(
            field, FieldSecretsArg.PATH
        )
        if secret_path is None:
            logger.debug("Skipping `%s`...", field.name)
            continue

        resp = _read_secret(client, secret_path, field)
        if resp is None:
            logger.warning("Skipping `%s`...", field.name)
            continue

        secret_key = _get_field_extra_arg(field, FieldSecretsArg.KEY)
        secret_data = _get_secret_data(settings, resp, secret_key, secret_path, field)

        if secret_data is None:
            logger.error("Wrong key `%s` for a secret at %s", secret_key, secret_path)
            logger.warning("Skipping `%s`...", field.name)
            continue

        vault_fields[field.alias] = secret_data
        logger.info("Field `%s` has been set.", field.name)

    logger.info("All fields have been processed with Vault!")
    return vault_fields


def _get_field_extra_arg(field: ModelField, arg: FieldSecretsArg) -> ty.Optional[str]:
    return field.field_info.extra.get(f"vault_secret_{arg.value}")


def _read_secret(
    client: VaultClient, secret_path: str, field: ModelField
) -> ty.Optional[JSONDict]:
    try:
        return client.read(secret_path)["data"]
    except VaultError:
        logger.exception("Failed to get a secret: %s", secret_path)
    except TypeError:
        # Response is None.
        logger.error("Invalid path to a secret: %s", secret_path)

    if field.required:
        raise ValueError(
            f"Couldn't set a value for `{field.name}`! The field is required."
        )
    return None


def _get_secret_data(
    settings: pydantic.BaseSettings,
    resp: JSONDict,
    secret_key: ty.Optional[str],
    secret_path: str,
    field: ModelField,
) -> ty.Any:
    secret_data = resp.get("data", resp)
    if secret_key is not None:
        secret_data = secret_data.get(secret_key)

    if (
        not field.is_complex()
        or secret_data is None
        or isinstance(secret_data, (dict, list))
    ):
        return secret_data

    try:
        return settings.__config__.json_loads(secret_data)
    except ValueError as e:
        raise SettingsError(f"JSON parsing error for {secret_path}") from e
