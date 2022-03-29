import pydantic


class VaultSettings(pydantic.BaseSettings):
    service_account_name: str
    env: str = "dev"
    enabled: bool = False
    secrets_path_prefix: str | None = None
    addr: str = "https://vault.infra.haut.ai"
    token: pydantic.SecretStr | None = None

    @pydantic.validator("secrets_path_prefix", pre=True, always=True)
    def set_prefix(
        cls,
        value: str | None,
        values: dict,
    ) -> str | None:
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
