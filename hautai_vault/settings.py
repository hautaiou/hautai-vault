import typing as ty

import pydantic


class VaultSettings(pydantic.BaseSettings):
    service_account_name: str
    env: str = "dev"
    enabled: bool = True
    secrets_path_prefix: ty.Optional[str] = None
    addr: str = "https://vault.infra.haut.ai"

    @pydantic.validator("secrets_path_prefix", pre=True, always=True)
    def set_prefix(
        cls,
        value: ty.Optional[str],
        values: dict,
    ) -> ty.Optional[str]:
        if values["enabled"]:
            env = values["env"]
            value = f"{env}/data"
        return value  # noqa: R504

    @property
    def role(self) -> str:
        return f"{self.env}-{self.service_account_name}"

    @property
    def auth_mount_point(self) -> str:
        return f"{self.env}_k8s"

    class Config:
        env_prefix: str = "vault_"
