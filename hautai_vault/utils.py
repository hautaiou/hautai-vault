"""Utility functions."""

__all__ = ["vault_settings_source", "write_secrets_into_temp_files"]

import json
import tempfile
import typing as ty
from contextlib import suppress
from pathlib import Path

from hvac.exceptions import VaultError
from pydantic import BaseSettings, SecretStr
from pydantic.env_settings import SettingsError
from pydantic.fields import ModelField

from .client import VaultClient
from .logger import logger
from .settings import VaultSettings

JSONDict = dict[str, ty.Any]


def write_secrets_into_temp_files(
    secrets: ty.Iterable[tuple[str, SecretStr]],
) -> dict[str, tempfile.NamedTemporaryFile]:
    temp_files = {}
    for key, value in secrets:
        secret = value.get_secret_value()
        temp_file = tempfile.NamedTemporaryFile()

        if isinstance(secret, dict):
            json.dump(secret, temp_file)
        else:
            temp_file.write(secret.encode())

        temp_file.seek(0)
        temp_files[key] = temp_file

    return temp_files


def vault_settings_source(settings: BaseSettings) -> JSONDict:
    vault_settings: VaultSettings = settings.__config__.vault_settings
    client = _setup_client(vault_settings)
    return _setup_fields(settings, client)


def _setup_client(vault_settings: VaultSettings) -> VaultClient:
    auth_token = _extract_auth_token(vault_settings)
    if auth_token is not None:
        return VaultClient(token=auth_token.get_secret_value(), url=vault_settings.addr)
    client = VaultClient(url=vault_settings.addr)
    client.auth(vault_settings)
    return client


def _extract_auth_token(vault_settings: VaultSettings) -> ty.Optional[SecretStr]:
    if vault_settings.token:
        logger.debug("Found Vault Token in environment variables")
        return vault_settings.token

    with suppress(FileNotFoundError), open(Path.home() / ".vault-token") as f:
        logger.debug("Vault auth token is taken from '~/.vault-token' file")
        return SecretStr(f.read().strip())

    return None


def _setup_fields(settings: BaseSettings, client: VaultClient) -> JSONDict:
    vault_fields: JSONDict = {}
    for field in settings.__fields__.values():
        secret_path: ty.Optional[str] = _get_secret_path(field)
        if secret_path is None:
            logger.debug("Skipping %s field...", field.name)
            continue

        resp = _get_response(client, secret_path, field)
        if resp is None:
            logger.debug("Applying the default for %s field...", field.name)
            continue

        secret_key = _get_secret_key(field)
        secret_data = _get_secret_data(settings, resp, secret_key, secret_path, field)

        vault_fields[field.alias] = secret_data
        logger.debug("Field %s is set to %s", field.name, secret_data)
    return vault_fields


def _get_secret_path(field: ModelField) -> ty.Optional[str]:
    return field.field_info.extra.get("vault_secret_path")


def _get_response(
    client: VaultClient, secret_path: str, field: ModelField
) -> ty.Optional[JSONDict]:
    try:
        return client.read(secret_path)["data"]
    except VaultError:
        logger.exception("Failed to get the following secret: %s", secret_path)
    except TypeError:
        # Response is None.
        logger.error("Invalid path to a secret: %s", secret_path)

    if field.required:
        raise ValueError(f"Couldn't set a value for a required field {field.name}")
    return None


def _get_secret_key(field: ModelField) -> ty.Optional[str]:
    return field.field_info.extra.get("vault_secret_key")


def _get_secret_data(
    settings: BaseSettings,
    resp: JSONDict,
    secret_key: ty.Optional[str],
    secret_path: str,
    field: ModelField,
) -> ty.Any:
    secret_data = resp.get("data", resp)
    if secret_key is not None:
        secret_path = ":".join((secret_path, secret_key))
        try:
            secret_data = secret_data[secret_key]
        except KeyError:
            logger.error("Wrong key for a secret! Full path: %s", secret_path)

    if not field.is_complex() or isinstance(secret_data, (dict, list)):
        return secret_data

    try:
        return settings.__config__.json_loads(secret_data)
    except ValueError as e:
        raise SettingsError(f"JSON parsing error for {secret_path}") from e
