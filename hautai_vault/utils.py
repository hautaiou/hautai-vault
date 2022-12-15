"""Internal utility functions."""

__all__ = ("maybe_read_auth_token_from_file", "write_secrets_into_temp_files")

import json
import tempfile
import typing as ty
from pathlib import Path

import pydantic

from .logger import logger


def maybe_read_auth_token_from_file(token_file: str) -> ty.Optional[pydantic.SecretStr]:
    abs_path = Path(token_file).expanduser()
    if not abs_path.exists():
        abs_path = Path.home() / token_file
    try:
        with abs_path.open() as file:
            logger.debug(f"Vault auth token is taken from {abs_path}.")
            return pydantic.SecretStr(file.read().strip())
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
