"""Vault settings."""

__all__ = ["VaultSettings"]

import logging
import typing as ty

import pydantic

from .logger import logger


class VaultSettings(pydantic.BaseSettings):
    """Provides the nessesary means to set up and use Hashicorp Vault.

    Fields:
        env -- only the secrets from a specific environment shall be awailable

        user_login -- user ID that the Vault client should auth against

        enabled -- can the Vault be used or not (default: {True})

        addr -- URL for the Vault instance being addressed (
            default: {"https://vault.infra.haut.ai"}
        )

        token -- Vault token for bypassing auth methods (default: {None})

        jwt -- JSON Web Token for JWT auth method (default: {None})

        secrets_path_prefix -- secrets engine backend's location prefix (
            default: {None}
        ). If None, results from prepending the current `env` value to the
        '/data' string literal, e.g.: "dev/data".

        secrets -- aliases to secrets' paths mapping (
            default: {"general": None}
        ). If None is assigned as an item's value instead of path to a secret,
        then an alias name will be used as a path.

        logging_level -- severity level of logging (default: {`logging.DEBUG`})

    Properties:
        role -- Vault auth role

        k8s_auth_mount_point -- mount point for K8s auth method
    """

    env: str
    user_login: str = pydantic.Field(
        ...,
        env=["vault_user_login", "service_account_name"],
    )
    enabled: bool = True
    addr: str = "https://vault.infra.haut.ai"
    token: ty.Union[pydantic.SecretStr, None] = None
    jwt: ty.Union[pydantic.SecretStr, None] = None
    secrets_path_prefix: ty.Optional[str] = None
    secrets: dict[str, ty.Optional[str]] = {"general": None}
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
            self.secrets[key] = f"{self.secrets_path_prefix}/{path.strip('/')}"

    @pydantic.validator("secrets_path_prefix", pre=True, always=True)
    def _set_secrets_path_prefix(
        cls,
        value: ty.Union[str, None],
        values: dict,
    ) -> ty.Union[str, None]:
        if values["enabled"] and value is None:
            try:
                env = values["env"]
            except KeyError:
                exit("VAULT_ENV environment variable is not specified!")
            return f"{env}/data"
        return value.strip("/")

    @property
    def role(self) -> str:
        return f"{self.env}-{self.user_login}"

    @property
    def k8s_auth_mount_point(self) -> str:
        return f"{self.env}_k8s"

    class Config:
        env_file: str = ".env"
        env_prefix: str = "vault_"
