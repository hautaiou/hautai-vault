import logging
import typing as ty

import pydantic


class VaultSettings(pydantic.BaseSettings):
    env: str
    service_account_name: str = pydantic.Field(
        ...,
        env=["service_account_name", "vault_service_account_name"],
    )
    secrets_names: ty.Iterable[str]
    enabled: bool = True
    addr: str = "https://vault.infra.haut.ai"
    token: ty.Union[pydantic.SecretStr, None] = None
    secrets_path_prefix: ty.Optional[str] = None
    secrets_paths: ty.Optional[dict[str, str]] = None
    logging_level: int = logging.DEBUG

    def _set_secrets_paths(self, secrets_names: ty.Iterable[str]) -> None:
        self.secrets_paths = {
            "general": f"{self.secrets_path_prefix}/general",
            "firebase": f"{self.secrets_path_prefix}/firebase",
        } | {
            secret: "{0}/sasuke/backend/{1}/{2}".format(
                self.secrets_path_prefix,
                self.service_account_name,
                secret,
            )
            for secret in secrets_names
        }

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        logging.basicConfig()
        logging.getLogger("pydantic-vault").setLevel(self.logging_level)

        if self.secrets_paths is None:
            self._set_secrets_paths(self.secrets_names)

    @pydantic.validator("secrets_path_prefix", pre=True, always=True)
    def set_prefix(
        cls,
        value: ty.Union[str, None],
        values: dict,
    ) -> ty.Union[str, None]:
        if values["enabled"]:
            try:
                env = values["env"]
            except KeyError:
                logging.exception("VAULT_ENV is not specified!")
                raise
            return f"{env}/data"
        return value

    @property
    def role(self) -> str:
        return f"{self.env}-{self.service_account_name}"

    @property
    def auth_mount_point(self) -> str:
        return f"{self.env}_k8s"

    class Config:
        env_file: str = ".env"
        env_prefix: str = "vault_"
