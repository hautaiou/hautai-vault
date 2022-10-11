"""Client setup."""

__all__ = [
    "AuthMethodParams",
    "JWTAuthMethodParams",
    "KubernetesAuthMethodParams",
    "VaultClient",
]

import typing as ty

import pydantic
import requests
from hvac import Client as HvacClient
from hvac.api.auth_methods import JWT, Kubernetes

from .logger import logger

if ty.TYPE_CHECKING:
    from .settings import VaultSettings

TOKEN_ABS_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"  # noqa: S105


class AuthMethodParams(pydantic.BaseModel):
    """Base parameters model for auth methods using JWTs.

    Fields:
        role -- Vault auth role

        jwt -- JSON Web Token

        use_token -- set `token` attr for an adapter in use (default: {True})
    """

    role: str
    jwt: ty.Any
    use_token: bool = True


class JWTAuthMethodParams(AuthMethodParams):
    """JWT-specific auth parameters.

    Extends `AuthMethodParams`.

    Fields:
        path -- auth method/backend mount point (default: {None})
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
        if settings.jwt is not None:
            logger.debug("Using the JWT auth method...")
            logger.debug("JWT value: %s", settings.jwt)
            auth_params = JWTAuthMethodParams(
                role=settings.role,
                jwt=settings.jwt,
            )
            return JWT(self.adapter).jwt_login(**auth_params.dict())

        logger.debug("Using the Kubernetes auth method...")
        auth_params = KubernetesAuthMethodParams(
            role=settings.role,
            jwt=self._get_k8s_jwt(),
            mount_point=settings.k8s_auth_mount_point,
        )
        return Kubernetes(self.adapter).login(**auth_params.dict())

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
