"""Vault settings."""

__all__ = ["VaultSettings"]

import logging
import typing as ty
from pathlib import PurePosixPath

import pydantic

from .logger import logger


class VaultSettings(pydantic.BaseSettings):
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
    secrets: dict[str, ty.Optional[PurePosixPath]] = {"general": None}
    logging_level: int = logging.DEBUG

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        logging.basicConfig()
        logging.getLogger(logger.name).setLevel(self.logging_level)

        self._set_secrets_paths()

    def _set_secrets_paths(self) -> None:
        for key, value in self.secrets.items():
            if value is None:
                self.secrets[key] = f"{self.secrets_path_prefix}/{key}"
                continue
            self.secrets[key] = f"{self.secrets_path_prefix}/{value.as_posix()}"

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
        return value

    @property
    def role(self) -> str:
        return f"{self.env}-{self.user_login}"

    @property
    def k8s_auth_mount_point(self) -> str:
        return f"{self.env}_k8s"

    class Config:
        env_file: str = ".env"
        env_prefix: str = "vault_"
