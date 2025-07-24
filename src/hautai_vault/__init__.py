import abc
import shlex
import subprocess
import typing as ty
from datetime import datetime
from functools import cache, cached_property
from pathlib import Path

import requests
from hvac import Client
from pydantic import BaseModel, Field, SecretStr
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


def get_session(
    total: int = 3,
    backoff_factor: float = 0.1,
    status_forcelist: ty.Iterable[int] | None = (412, 500, 502, 503),
    raise_on_status: bool = False,
) -> requests.Session:
    adapter = HTTPAdapter(
        max_retries=Retry(
            total=total,
            backoff_factor=backoff_factor,
            status_forcelist=None if status_forcelist is None else set(status_forcelist),
            raise_on_status=raise_on_status,
        ),
    )
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


class AbstractVaultAuthMethod(BaseSettings):
    role: str = Field(..., alias="vault_auth_role")

    @abc.abstractmethod
    def get_authorized_client(self) -> Client:
        pass

    model_config = SettingsConfigDict(env_file=".env")


# https://learn.microsoft.com/en-us/dotnet/api/microsoft.azure.commands.profile.models.psaccesstoken?view=az-ps-latest
class PSAccessToken(BaseModel):
    access_token: str = Field(..., alias="accessToken")
    expires_on: datetime = Field(..., alias="expiresOn")
    subscription: str
    tenant: str
    token_type: str = Field(..., alias="tokenType")


class AzureAuthMethod(AbstractVaultAuthMethod):
    mount_point: str = "azure"

    def get_authorized_client(self) -> Client:
        # https://learn.microsoft.com/en-us/powershell/module/az.accounts/get-azaccesstoken?view=azps-11.0.0
        ret = subprocess.run(  # noqa: S602
            shlex.join(split_command=["az", "account", "get-access-token"]),
            shell=True,
            capture_output=True,
            check=True,
        )

        ps_access_token = PSAccessToken.model_validate_json(ret.stdout)

        client = Client(url=get_vault_settings().url, session=get_session())
        client.auth.azure.login(
            self.role,
            ps_access_token.access_token,
            mount_point=self.mount_point,
        )
        return client

    model_config = SettingsConfigDict(env_prefix="VAULT_AUTH_AZURE_")


class JWTAuthMethod(AbstractVaultAuthMethod):
    path: str | None = None
    token: SecretStr

    def get_authorized_client(self) -> Client:
        client = Client(url=get_vault_settings().url, session=get_session())
        client.auth.jwt.jwt_login(
            role=self.role,
            jwt=self.token.get_secret_value(),
            path=self.path,
        )
        return client

    model_config = SettingsConfigDict(env_prefix="VAULT_AUTH_JWT_")


class K8sAuthMethod(AbstractVaultAuthMethod):
    token_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"  # noqa: S105
    mount_point: str

    def get_authorized_client(self) -> Client:
        client = Client(url=get_vault_settings().url, session=get_session())
        client.auth.kubernetes.login(
            self.role,
            self._get_token(),
            mount_point=self.mount_point,
        )
        return client

    def _get_token(self) -> str:
        try:
            return Path(self.token_path).read_text().strip()
        except FileNotFoundError as e:
            msg = f"Kubernetes service account signed jwt at `{self.token_path}` is not found!"
            raise ValueError(
                msg,
            ) from e

    model_config = SettingsConfigDict(env_prefix="VAULT_AUTH_K8S_")


_VAULT_AUTH_METHODS: dict[str, type[AbstractVaultAuthMethod]] = {
    "jwt": JWTAuthMethod,
    "azure": AzureAuthMethod,
    "k8s": K8sAuthMethod,
}


def register_vault_auth_method(
    auth_method: str,
    auth_method_class: type[AbstractVaultAuthMethod],
) -> None:
    _VAULT_AUTH_METHODS[auth_method] = auth_method_class


class VaultBaseConfig(BaseSettings):
    model_config = SettingsConfigDict(
        extra="allow",
        env_file=".env",
        env_prefix="VAULT_",
    )


class VaultBasicSettings(VaultBaseConfig):
    enabled: bool = True


class VaultSettings(VaultBasicSettings):
    enabled: bool = True
    url: str
    auth_method: str | None = None
    mount_point: str = "dev"


@cache
def is_vault_enabled() -> bool:
    """Check if Vault is enabled."""
    return VaultBasicSettings().enabled


@cache
def get_vault_settings() -> VaultSettings:
    return VaultSettings()


class VaultSettingsSource(PydanticBaseSettingsSource):
    @cached_property
    def _secrets(self) -> dict[str, ty.Any]:
        if not is_vault_enabled():
            return {}

        auth_method_cls: type[AbstractVaultAuthMethod] | None = None

        vault_settings = get_vault_settings()
        if vault_settings.auth_method is not None:
            try:
                auth_method_cls = _VAULT_AUTH_METHODS[vault_settings.auth_method]
            except KeyError as e:
                msg = f"Vault auth method `{vault_settings.auth_method}` is not supported"
                raise ValueError(
                    msg,
                ) from e

        if auth_method_cls is None:
            # Default auth method is by token (VAULT_TOKEN env var or ~/.vault-token)
            client = Client(url=vault_settings.url, session=get_session())
        else:
            client = auth_method_cls().get_authorized_client()

        assert issubclass(self.settings_cls, VaultBaseSettings)

        return client.secrets.kv.v2.read_secret_version(
            self.settings_cls.secret_path,
            mount_point=vault_settings.mount_point,
            raise_on_deleted_version=True,
        )["data"]["data"]

    def prepare_field_value(
        self,
        field_name: str,
        field: FieldInfo,
        value: ty.Any,
        value_is_complex: bool,
    ) -> ty.Any:
        return value

    def get_field_value(
        self,
        field: FieldInfo,
        field_name: str,
    ) -> tuple[ty.Any, str, bool]:
        field_value = self._secrets.get(field_name)
        return field_value, field_name, False

    def __call__(self) -> dict[str, ty.Any]:
        data = {}
        for field_name, field in self.settings_cls.model_fields.items():
            field_value, field_key, value_is_complex = self.get_field_value(
                field,
                field_name,
            )
            field_value = self.prepare_field_value(
                field_name,
                field,
                field_value,
                value_is_complex,
            )
            if field_value is not None:
                data[field_key] = field_value
        return data


class VaultBaseSettings(BaseSettings):
    secret_path: ty.ClassVar[str]

    def __init_subclass__(cls, /, secret_path: str, **kwargs: ty.Any) -> None:
        super().__init_subclass__(**kwargs)
        cls.secret_path = secret_path

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            env_settings,
            dotenv_settings,
            init_settings,
            VaultSettingsSource(settings_cls),
            file_secret_settings,
        )

    model_config = SettingsConfigDict(extra="allow", env_file=".env")
