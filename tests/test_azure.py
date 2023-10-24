from hautai_vault.client import VaultClient
from hautai_vault.settings import VaultSettings


def test_azure_login():
    settings = VaultSettings(
        azure=True,
        env="test",
        jwt="aaa",
        user_login="test",
    )
    client = VaultClient(url="https://vault.infra.haut.ai", token=settings.jwt)
    client.auth(settings=settings)
    assert False
