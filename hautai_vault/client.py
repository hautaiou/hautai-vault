"""Client setup."""

__all__ = (
    "AuthMethodParams",
    "JWTAuthMethodParams",
    "KubernetesAuthMethodParams",
    "VaultClient",
)

import enum
import typing as ty

import pydantic
import requests
from hvac import Client as HvacClient
from hvac.api.auth_methods import JWT, Azure, Kubernetes

from .logger import logger

if ty.TYPE_CHECKING:
    from .settings import VaultSettings

TOKEN_ABS_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"  # noqa: S105


class AuthMethod(str, enum.Enum):
    AZURE = "azure"
    JWT = "jwt"
    K8S = "k8s"


class AuthMethodParams(pydantic.BaseModel):
    """Base parameters model for auth methods using JWTs.

    Fields:
        role -- Vault auth role

        jwt -- JSON Web Token

        use_token -- set `token` attr for an adapter in use (default: {`True`})
    """

    role: str
    jwt: str
    use_token: bool = True


class AzureAuthMethodParams(AuthMethodParams):
    """Azure auth method parameters.

    Extends `AuthMethodParams`.

    Fields:
        subscription_id -- subscription ID for the machine that generated the
        MSI token. Can be obtained via instance metadata (default: {`None`})

        resource_group_name -- resource group for the machine that generated
            the MSI token. Can be obtained via instance metadata
            (default: {`None`})

        vm_name -- virtual machine name for the machine that generated the
            MSI token. If vmss_name is provided, this value is ignored.
            Can be obtained via instance metadata (default: {`None`})

        vmss_name -- virtual machine scale set name for the machine that
            generated the MSI token. Can be obtained via instance metadata
            (default: {`None`})

        mount_point -- auth method mount point (default: {"azure"})
    """

    subscription_id: ty.Optional[str] = None
    resource_group_name: ty.Optional[str] = None
    vm_name: ty.Optional[str] = None
    vmss_name: ty.Optional[str] = None
    mount_point: str = "azure"


class JWTAuthMethodParams(AuthMethodParams):
    """JWT-specific auth parameters.

    Extends `AuthMethodParams`.

    Fields:
        path -- auth method/backend mount point (default: {`None`})
    """

    path: ty.Optional[str] = None


class KubernetesAuthMethodParams(AuthMethodParams):
    """K8s-specific auth parameters.

    Extends `AuthMethodParams`.

    Fields:
        mount_point -- auth method mount point
    """

    mount_point: str


class VaultClient(HvacClient):
    """Interacts with Vault API.

    Extends the base `hvac.Client` class.

    Methods:
        auth -- login via one of the auth methods
    """

    def auth(self, settings: "VaultSettings") -> requests.Response:
        """Login via one of the auth methods.

        Currently, there are only two methods supported. Depending on whether
        `settings.jwt` is provided, either the JWT or the Kubernetes methods
        are used.

        Arguments:
            settings -- `VaultSettings` instance

        Returns:
            An HTTP response.
        """
        auth_method = self._set_auth_method(settings)
        if auth_method is AuthMethod.K8S:
            logger.debug("Using the Kubernetes auth method...")
            auth_params = KubernetesAuthMethodParams(
                role=settings.auth_role,
                jwt=self._get_k8s_jwt(),
                mount_point=settings.auth_path,
            )
            return Kubernetes(self.adapter).login(**auth_params.dict())
        if auth_method is AuthMethod.JWT:
            logger.debug("Using the JWT auth method...")
            auth_params = JWTAuthMethodParams(
                role=settings.auth_role,
                jwt=settings.jwt.get_secret_value(),
                path=settings.auth_path,
            )
            return JWT(self.adapter).jwt_login(**auth_params.dict())
        logger.debug("Using the Azure auth method...")
        auth_params = AzureAuthMethodParams(role=settings.auth_role, jwt=settings.jwt)
        return Azure(self.adapter).login(**auth_params.dict())

    def _set_auth_method(self, settings: "VaultSettings") -> AuthMethod:
        if settings.auth_path is not None and settings.auth_path.endswith("_k8s"):
            return AuthMethod.K8S
        if settings.jwt is not None:
            if settings.auth_path == "gitlab":
                return AuthMethod.JWT
            return AuthMethod.AZURE
        raise ValueError("Couldn't determine a proper auth method.")

    def _get_k8s_jwt(self) -> str:
        try:
            with open(TOKEN_ABS_PATH) as f:
                return f.read().strip()
        except FileNotFoundError:
            logger.error(
                "K8s service account token is not found! Expected path: %s",
                TOKEN_ABS_PATH,
            )
            raise
