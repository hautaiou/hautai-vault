from hautai_vault.client import VaultClient
from hautai_vault.settings import VaultSettings


def test_azure_login():
    settings = VaultSettings(
        azure=True,
        env="dev",
        auth_role="vault-ds",
        auth_path="azure",
    )
    client = VaultClient(url="https://vault.infra.haut.ai", token=settings.jwt)
    client.auth(settings=settings)
    assert client.is_authenticated
    full_vault_resp = client.read("/dev/data/ds/test")
    assert full_vault_resp is not None
    assert full_vault_resp["data"]["data"] == {"test2": "test"}
