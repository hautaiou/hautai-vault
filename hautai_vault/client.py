"""Client setup."""

__all__ = (
    "AzureAuthMethodParams",
    "BaseAuthMethodParams",
    "JWTAuthMethodParams",
    "KubernetesAuthMethodParams",
    "VaultClient",
)

import enum
import json
import shlex
import subprocess
import typing as ty
from datetime import datetime

import pydantic
from azure.identity import AzureCliCredential
from hvac import Client as HvacClient
from hvac.api.auth_methods import JWT, Azure, Kubernetes

from .logger import logger

if ty.TYPE_CHECKING:
    from requests import Response

    from .settings import VaultSettings

K8S_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"  # noqa: S105


class AuthMethod(str, enum.Enum):
    AZURE = "azure"
    JWT = "jwt"
    K8S = "k8s"


class BaseAuthMethodParams(pydantic.BaseModel):
    """Base parameters model for auth methods using JWTs.

    Fields:
        role -- Vault auth role

        jwt -- JSON Web Token

        use_token -- set `token` attr for an adapter in use (default: {`True`})
    """

    role: str
    jwt: str
    use_token: bool = True


class AzureAuthMethodParams(BaseAuthMethodParams):
    """Azure auth method parameters.

    Extends `BaseAuthMethodParams`.

    Fields:
        mount_point -- auth method mount point (default: {"azure"})
    """

    mount_point: str = "azure"


class JWTAuthMethodParams(BaseAuthMethodParams):
    """JWT auth method parameters.

    Extends `BaseAuthMethodParams`.

    Fields:
        path -- auth method/backend mount point (default: {`None`})
    """

    path: ty.Optional[str] = None


class KubernetesAuthMethodParams(BaseAuthMethodParams):
    """Kubernetes auth method parameters.

    Extends `BaseAuthMethodParams`.

    Fields:
        mount_point -- auth method mount point
    """

    mount_point: str


class AzTokenResp(pydantic.BaseModel):
    accessToken: pydantic.SecretStr
    expiresOn: datetime
    subscription: str
    tenant: str
    tokenType: str


class AzureCliError(Exception):
    ...


class VaultClient(HvacClient):
    """Interacts with Vault API.

    Extends the base `hvac.Client` class.

    Methods:
        auth -- login via one of the auth methods
    """

    def auth(self, settings: "VaultSettings") -> "Response":
        """Login via one of the auth methods.

        Available methods, in the order of precedence:
            1) Azure
            2) JWT
            3) Kubernetes

        Arguments:
            settings -- `VaultSettings` instance

        Returns:
            an HTTP response
        """
        auth_method = self._get_auth_method(settings)

        if auth_method is AuthMethod.AZURE:
            # azure_token = AzureCliCredential().get_token("openid")
            cmd = shlex.join(split_command=["az", "account", "get-access-token"])
            try:
                azure_token = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    check=True,
                )
            except subprocess.CalledProcessError as e:
                raise AzureCliError(str(e.stderr)) from e

            parsed = AzTokenResp.parse_raw(azure_token.stdout)
            auth_params = AzureAuthMethodParams(
                role=settings.auth_role,
                jwt=parsed.accessToken.get_secret_value(),
            )
            if isinstance(self.adapter.token, pydantic.SecretStr):
                self.adapter.token = self.adapter.token.get_secret_value()
            return Azure(self.adapter).login(**auth_params.dict())

        if auth_method is AuthMethod.JWT:
            auth_params = JWTAuthMethodParams(
                role=settings.auth_role,
                jwt=settings.jwt.get_secret_value(),
                path=settings.auth_path,
            )
            return JWT(self.adapter).jwt_login(**auth_params.dict())

        auth_params = KubernetesAuthMethodParams(
            role=settings.auth_role,
            jwt=self._get_k8s_token(),
            mount_point=settings.auth_path,
        )
        return Kubernetes(self.adapter).login(**auth_params.dict())

    def _get_auth_method(self, settings: "VaultSettings") -> AuthMethod:
        if settings.azure:
            logger.debug("Using the Azure auth method")
            return AuthMethod.AZURE
        if settings.jwt is not None:
            logger.debug("Using the JWT auth method")
            return AuthMethod.JWT
        if settings.auth_path.endswith("_k8s"):
            logger.debug("Using the Kubernetes auth method")
            return AuthMethod.K8S
        raise ValueError("Couldn't determine a proper Vault auth method")

    def _get_k8s_token(self) -> ty.Optional[str]:
        try:
            with open(K8S_TOKEN_PATH) as file:
                return file.read().strip()
        except FileNotFoundError:
            logger.exception(
                "K8s service account token is not found! Expected path: %s",
                K8S_TOKEN_PATH,
            )
