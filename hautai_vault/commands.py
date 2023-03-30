"""The command pattern implementations."""

__all__ = ("GetVaultSecrets",)

import enum
import typing as ty
from dataclasses import dataclass, field

from hvac.exceptions import VaultError
from pydantic.env_settings import SettingsError

from .logger import logger
from .utils import boldify

if ty.TYPE_CHECKING:
    from pydantic import BaseSettings
    from pydantic.fields import ModelField
    from pydantic.typing import DictStrAny

    from .client import VaultClient


class ArgType(str, enum.Enum):
    KEY = "vault_secret_key"
    PATH = "vault_secret_path"


@dataclass(eq=False, match_args=False)
class GetVaultSecrets:
    settings: "BaseSettings"
    client: "VaultClient"
    responses_cache: "dict[str, DictStrAny]" = field(default_factory=dict, compare=False)

    def execute(self) -> "DictStrAny":
        logger.info("Attempting to fill fields with Vault secrets' data...")

        processed_fields: "DictStrAny" = {}
        for model_field in self.settings.__fields__.values():
            path: ty.Optional[str] = model_field.field_info.extra.get(ArgType.PATH.value)
            if path is None:
                continue

            secret = self._fetch_secret_from_cache(path)
            if secret is None:
                logger.debug("Skipping %s field", boldify(model_field.name))
                continue

            key = model_field.field_info.extra.get(ArgType.KEY.value)
            secret_data = self._get_secret_data(secret, key, path, model_field)
            if secret_data is None:
                logger.error(
                    "Unable to fetch secret data for %s field",
                    boldify(model_field.name),
                )
                continue

            processed_fields[model_field.alias] = secret_data
            logger.info("Field %s has been set", boldify(model_field.name))

        logger.info("...Done")
        return processed_fields

    def _fetch_secret_from_cache(self, path: str) -> "ty.Optional[DictStrAny]":
        try:
            return self.responses_cache[path]
        except KeyError:
            self.responses_cache[path] = self._read_secret(path)
        return self.responses_cache[path]

    def _read_secret(self, path: str) -> "ty.Optional[DictStrAny]":
        try:
            return self.client.read(path)["data"]
        except VaultError:
            logger.exception("Unable to read a secret at %s", path)
        except TypeError:  # Response is None.
            logger.error("Invalid path to a secret: %s", path)
        return None

    def _get_secret_data(
        self,
        secret: "DictStrAny",
        key: ty.Optional[str],
        path: str,
        model_field: "ModelField",
    ) -> ty.Any:
        secret_data = secret.get("data", secret)
        if key is not None:
            secret_data = secret_data.get(key)

        if model_field.is_complex() and not isinstance(secret_data, (dict, list)):
            try:
                return self.settings.__config__.json_loads(secret_data)
            except ValueError as exc:
                raise SettingsError(f"Parsing error for a secret at {path}") from exc

        return secret_data
