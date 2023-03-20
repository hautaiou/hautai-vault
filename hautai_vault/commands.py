"""The command pattern implementations."""

__all__ = ("GetVaultSecrets",)

import enum
import typing as ty
from dataclasses import dataclass

from hvac.exceptions import VaultError
from pydantic.env_settings import SettingsError

from .logger import logger

if ty.TYPE_CHECKING:
    from pydantic import BaseSettings
    from pydantic.fields import ModelField

    from .client import VaultClient


class ArgType(str, enum.Enum):
    KEY = "vault_secret_key"
    PATH = "vault_secret_path"


DictStrAny = dict[str, ty.Any]


@dataclass
class GetVaultSecrets:
    settings: "BaseSettings"
    client: "VaultClient"

    def execute(self) -> DictStrAny:
        logger.info("Attempting to fill fields with Vault secrets' data...")

        vault_fields: DictStrAny = {}
        for field in self.settings.__fields__.values():
            path: ty.Optional[str] = field.field_info.extra.get(ArgType.PATH.value)
            if path is None:
                continue

            secret = self._read_secret(path)
            if secret is None:
                logger.debug("Skipping `%s` field", field.name)
                continue

            key = field.field_info.extra.get(ArgType.KEY.value)
            secret_data = self._get_secret_data(secret, key, path, field)

            if secret_data is None:
                logger.error("Unable to set secret data for `%s` field", field.name)
                continue

            vault_fields[field.alias] = secret_data
            logger.info("Field `%s` has been set", field.name)

        logger.info("Done")
        return vault_fields

    def _read_secret(self, path: str) -> ty.Optional[DictStrAny]:
        try:
            return self.client.read(path)["data"]
        except VaultError:
            logger.exception("Unable to read a secret at %s", path)
        except TypeError:
            # Response is None.
            logger.error("Invalid path to a secret: %s", path)

    def _get_secret_data(
        self,
        secret: DictStrAny,
        key: ty.Optional[str],
        path: str,
        field: "ModelField",
    ) -> ty.Any:
        if key is None:
            secret_data = secret.get("data", secret)
        else:
            secret_data = secret.get("data", secret).get(key)

        if (
            secret_data is None
            or field.is_complex()
            and isinstance(secret_data, (dict, list))
        ):
            return secret_data

        try:
            return self.settings.__config__.json_loads(secret_data)
        except ValueError as exc:
            raise SettingsError(f"JSON parsing error for a secret at {path}") from exc
