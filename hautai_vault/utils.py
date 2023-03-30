"""Internal utility functions."""

__all__ = ("boldify", "read_auth_token_from_file", "write_secrets_into_temp_files")

import json
import tempfile
import typing as ty
from pathlib import Path

import pydantic

from .logger import logger


def boldify(text: str) -> str:
    return f"\033[1m{text}\033[0m"


def read_auth_token_from_file(token_path: str) -> ty.Optional[pydantic.SecretStr]:
    try:
        parsed_path = Path(token_path).expanduser()
    except RuntimeError:
        logger.error("Token path is invalid")
        return None

    if not parsed_path.exists():
        parsed_path = Path.home() / token_path

    try:
        token_file = parsed_path.open()
    except FileNotFoundError:
        logger.error("Token path is invalid")
        return None

    token = token_file.read().strip()
    token_file.close()

    logger.debug("Got an auth token from %s", parsed_path)
    return pydantic.SecretStr(token)


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
