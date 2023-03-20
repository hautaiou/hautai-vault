import os
import typing as ty

import pytest

from ..hautai_vault.utils import read_auth_token_from_file

if ty.TYPE_CHECKING:
    from pathlib import Path

TOKEN_FILE_NAME = ".vault-token"


@pytest.fixture(autouse=True, scope="session")
def token_unset() -> None:
    os.environ.pop("VAULT_TOKEN", None)


@pytest.fixture(scope="session")
def invalid_token_path() -> None:
    os.environ["VAULT_TOKEN_PATH"] = "~~"
    yield
    del os.environ["VAULT_TOKEN_PATH"]


@pytest.fixture
def token_tmp_path(tmp_path: "Path") -> "Path":
    vault_tests_path = tmp_path / "vault_tests"
    vault_tests_path.mkdir(exist_ok=True)

    token = read_auth_token_from_file(TOKEN_FILE_NAME)
    token_path = vault_tests_path / TOKEN_FILE_NAME
    token_path.write_text(token.get_secret_value())

    return token_path
