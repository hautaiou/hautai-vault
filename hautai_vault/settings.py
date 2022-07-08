import logging
import typing as ty

import pydantic


class VaultSettings(pydantic.BaseSettings):
    service_account_name: ty.Optional[str] = None
    env: str = "dev"
    enabled: bool = True
    addr: str = "https://vault.infra.haut.ai"
    token: ty.Union[pydantic.SecretStr, None] = None
    secrets_names: ty.Optional[ty.Iterable[str]] = None
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
            env = values["env"]
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
