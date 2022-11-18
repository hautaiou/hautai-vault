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

        token -- Vault token for bypassing auth methods (default: {None})

        jwt -- JSON Web Token for JWT auth method (default: {None})

        auth_role -- Vault auth role (default: {None})

        secrets -- aliases to secrets' paths mapping (
            default: {"general": None}
        ). If None is assigned as an item's value instead of path to a secret,
        then an alias name will be used as a path.

        secrets_mount_point -- KV storage mount point, i.e. path prefix (default: {None})

        logging_level -- severity level of logging (default: {`logging.DEBUG`})

    Properties:
        auth_role -- current auth role

        auth_mount_point -- mount point for a current auth method
    """

    user_login: str = pydantic.Field(
        ...,
        env=["vault_user_login", "service_account_name"],
    )
    enabled: bool = True
    addr: str = "https://vault.infra.haut.ai"

    token: ty.Optional[pydantic.SecretStr] = None
    jwt: ty.Optional[pydantic.SecretStr] = None

    auth_role: ty.Optional[str] = None

    secrets: dict[str, ty.Optional[str]] = {"general": None}
    secrets_mount_point: ty.Optional[str] = None

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
            self.secrets[key] = f"{self.secrets_mount_point}/data/{path.strip('/')}"

    @pydantic.validator("auth_role", pre=True, always=True)
    def _set_auth_role(
        cls, value: ty.Optional[str], values: dict[str, ty.Any]
    ) -> ty.Optional[str]:
        if value is not None:
            return value
        return f"{values['secrets_mount_point']}-{values['user_login']}"

    @pydantic.validator("secrets_mount_point", pre=True, always=True)
    def _set_secrets_mount_point(cls, value: ty.Optional[str]) -> ty.Optional[str]:
        if value is not None:
            return value.strip("/")
        return "secrets"

    class Config:
        env_file: str = ".env"
        env_prefix: str = "vault_"
