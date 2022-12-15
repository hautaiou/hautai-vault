import os
import typing as ty
from pathlib import Path

import pydantic
import pytest

from ..hautai_vault.utils import maybe_read_auth_token_from_file

TOKEN_FILE = ".vault-token"


@pytest.fixture
def vault_token_path(tmp_path: Path):
    vault_tests_path = tmp_path / "vault_tests"
    vault_tests_path.mkdir(exist_ok=True)
    temp_token_path = vault_tests_path / TOKEN_FILE

    token_file = Path(os.getenv("VAULT_TOKEN_FILE", TOKEN_FILE))
    token = maybe_read_auth_token_from_file(token_file)
    assert token is not None

    temp_token_path.write_text(token.get_secret_value())
    return temp_token_path
