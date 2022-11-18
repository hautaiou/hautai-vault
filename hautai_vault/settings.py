"""Vault settings."""

__all__ = ["VaultSettings"]

import logging
import typing as ty

import pydantic

from .logger import logger


class VaultSettings(pydantic.BaseSettings):
    """Provides the nessesary means to set up and use Hashicorp Vault.

    Fields:
        user_login -- user ID that the Vault client should auth against

        enabled -- can the Vault be used or not (default: {True})

        addr -- URL for the Vault instance being addressed (
            default: {"https://vault.infra.haut.ai"}
        )

        env -- current K8s env. Usually used by our services (default: {None})

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

    user_login: str = pydantic.Field(
        ...,
        env=["vault_user_login", "service_account_name"],
    )
    enabled: bool = True
    addr: str = "https://vault.infra.haut.ai"
    env: ty.Optional[str] = None

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

    @pydantic.validator("secrets_engine", pre=True, always=True)
    def _set_secrets_engine(
        cls, value: ty.Optional[str], values: dict[str, ty.Any]
    ) -> ty.Union[str, ty.NoReturn]:
        if value is not None:
            return value.strip("/")
        if values["env"] is not None:
            return values["env"]
        exit("Either VAULT_SECRETS_ENGINE or VAULT_ENV envs must be set!")

    @pydantic.validator("auth_role", pre=True, always=True)
    def _set_auth_role(cls, value: ty.Optional[str], values: dict[str, ty.Any]) -> str:
        if value is not None:
            return value
        if values["env"] is not None:
            return f"{values['env']}-{values['user_login']}"
        exit("Either VAULT_AUTH_ROLE or VAULT_ENV envs must be set!")

    @pydantic.validator("auth_path", pre=True, always=True)
    def _set_auth_path(
        cls, value: ty.Optional[str], values: dict[str, ty.Any]
    ) -> str:
        if value is not None:
            return value.strip("/")
        if values["env"] is not None:
            return f"{values['env']}_k8s"
        exit("Either VAULT_AUTH_PATH or VAULT_ENV envs must be set!")

    class Config:
        env_file: str = ".env"
        env_prefix: str = "vault_"
