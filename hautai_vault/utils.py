"""Utility functions."""

__all__ = ("get_auth_token_from_homedir", "write_secrets_into_temp_files")

import json
import tempfile
import typing as ty
from pathlib import Path

import pydantic

from .logger import logger


def get_auth_token_from_homedir() -> ty.Optional[pydantic.SecretStr]:
    try:
        with open(Path.home() / ".vault-token") as f:
            logger.debug("Vault auth token is taken from '~/.vault-token' file")
            return pydantic.SecretStr(f.read().strip())
    except FileNotFoundError:
        return None


def write_secrets_into_temp_files(
    secrets: ty.Iterable[tuple[str, pydantic.SecretStr]],
) -> dict[str, tempfile.NamedTemporaryFile]:
    """Write each secret in an iterable into a temporary file.

    Arguments:
        secrets -- iterable of secrets' names and data tuples

    Returns:
        a dictionary with secrets' names as keys and tempfiles as values
    """
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
