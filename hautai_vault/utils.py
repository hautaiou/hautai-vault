import json
import tempfile
import typing as ty

import pydantic
import pydantic_vault


def get_vault_settings_source() -> dict[str, ty.Any]:
    return pydantic_vault.vault_config_settings_source


def write_secrets_into_temp_files(
    secrets: ty.Iterable[tuple[str, pydantic.SecretStr]],
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
