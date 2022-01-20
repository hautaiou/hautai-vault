import pydantic_vault


def include_vault_settings_into_sources(
    init_settings,
    env_settings,
    file_secret_settings,
) -> tuple:
    return (
        init_settings,
        env_settings,
        pydantic_vault.vault_config_settings_source,
        file_secret_settings,
    )
