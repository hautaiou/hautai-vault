"""Vault settings."""

__all__ = ("VaultSettings", "vault_settings_source")

import enum
import logging
import typing as ty

import pydantic
from hvac.exceptions import VaultError
from pydantic.env_settings import SettingsError
from pydantic.fields import ModelField

from .client import VaultClient
from .logger import logger
from .utils import maybe_read_auth_token_from_file


class VaultSettings(pydantic.BaseSettings):
    """Provides the nessesary means to set up and use Hashicorp Vault.

    Fields:
        enabled -- can the Vault be used or not (default: {`True`})

        addr -- URL for the Vault instance being addressed
            (default: {"https://vault.infra.haut.ai"})

        env -- current K8s env for backend services (default: {`None`})

        user_login -- used as a fallback auth role together with env
            (default: {`None`})

        token_file -- file name or path, either relative or absolute, from
            which an auth token should be read (default: {".vault-token"})

        token -- Vault token for bypassing auth methods (default: {`None`})

        jwt -- JSON Web Token for JWT auth method (default: {`None`})

        secrets -- mapping of aliases to secrets' paths. `None` can be used
            in values as a shortcut to interpret an alias as a path,
            e.g. {"foo": `None`} will be resolved to
            {"foo": "`self.secrets_engine`/data/foo"}.
            NOTE: when specifying a path, omit the "prefix/data/" part,
            i.e. "`self.secrets_engine`/data/path/to/a/secret" is WRONG,
            but "path/to/a/secret" is CORRECT (default: {"general": `None`})

        secrets_engine -- KV storage mount point (default: {`None`})

        auth_role -- Vault auth role (default: {`None`})

        auth_path -- auth login method path (default: {`None`})

        logging_level -- severity level of logging (default: {`logging.DEBUG`})
    """

    enabled: bool = True
    addr: str = "https://vault.infra.haut.ai"

    env: ty.Optional[str] = None
    user_login: ty.Optional[str] = pydantic.Field(
        None,
        env=["vault_user_login", "service_account_name"],
    )

    token_file: str = ".vault-token"
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

        if self.enabled:
            self._set_secrets_paths()

    def _set_secrets_paths(self) -> None:
        prefix = self.secrets_engine or self.env
        if prefix is None:
            raise ValueError(
                "Either `secrets_engine` or `env` fields must not be `None` "
                "for constructing proper paths to Vault secrets. "
                "You may pass the corresponding keyword arguments when "
                "instantiating the `VaultSettings` class programmatically. "
                "Otherwise, consider setting `VAULT_SECRETS_ENGINE`, "
                "`VAULT_ENV`, or both environment variables "
                "to (a) non-empty value(-s)."
            )
        for key, value in self.secrets.items():
            path = key if value is None else value
            self.secrets[key] = f"{prefix}/data/{path.strip('/')}"

    @pydantic.validator("token", always=True)
    def _set_token(
        cls, value: ty.Optional[pydantic.SecretStr], values: dict[str, ty.Any]
    ) -> ty.Optional[pydantic.SecretStr]:
        if value is not None:
            logger.debug("Found Vault auth token in environment variables.")
            return value
        return maybe_read_auth_token_from_file(values["token_file"])

    @pydantic.validator("auth_role", always=True)
    def _set_auth_role(
        cls, value: ty.Optional[str], values: dict[str, ty.Any]
    ) -> ty.Optional[str]:
        if (
            value is not None
            or values["token"] is not None
            or values["enabled"] is False
        ):
            return value
        if values["env"] is not None and values["user_login"] is not None:
            return f"{values['env']}-{values['user_login']}"
        raise ValueError(
            "Either `auth_role` or both `env` and `user_login` fields "
            "must not be `None` to authenticate via K8s or JWT "
            "auth methods in production. "
            "You may pass the corresponding keyword arguments when "
            "instantiating the `VaultSettings` class programmatically. "
            "Otherwise, consider setting `VAULT_AUTH_ROLE` or both "
            "`VAULT_ENV` and `VAULT_USER_LOGIN ` environment variables "
            "to (a) non-empty value(-s)."
            "For a local development, you could instead:\n"
            "1) provide an auth token via `VAULT_TOKEN` env var or "
            "pass it as a keyword argument in the class' constructor;\n"
            "2) login via Vault CLI prior to executing the script.\n"
            "If your token file resembles in a non-default place "
            "(~/.vault-token), you may point to it by setting an env var "
            "VAULT_TOKEN_FILE or the corresponding class attribute."
        )

    @pydantic.validator("auth_path", always=True)
    def _set_auth_path(
        cls, value: ty.Optional[str], values: dict[str, ty.Any]
    ) -> ty.Optional[str]:
        if (
            value is not None
            or values["token"] is not None
            or values["enabled"] is False
        ):
            return value
        if values["env"] is not None:
            return f"{values['env']}_k8s"
        raise ValueError(
            "Either `auth_path` or `env` fields must not be `None` "
            "to authenticate via K8s or JWT auth methods in production. "
            "You may pass the corresponding keyword arguments when "
            "instantiating the `VaultSettings` class programmatically. "
            "Otherwise, consider setting `VAULT_AUTH_PATH`, `VAULT_ENV`, "
            "or both environment variables to (a) non-empty value(-s)."
            "For a local development, you could instead:\n"
            "1) provide an auth token via `VAULT_TOKEN` env var or "
            "pass it as a keyword argument in the class' constructor;\n"
            "2) login via Vault CLI prior to executing the script.\n"
            "If your token file resembles in a non-default place "
            "(~/.vault-token), you may point to it by setting an env var "
            "VAULT_TOKEN_FILE or the corresponding class attribute."
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
        secret_path: ty.Optional[str] = _get_field_extra_arg(field, FieldSecretsArg.PATH)
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
