.DEFAULT_GOAL:=help
SHELL:=/bin/bash

.EXPORT_ALL_VARIABLES:
PYTHONPATH:=./

WHEEL_REPO:=haut_ai
PACKAGE_NAME:=hautai_vault

help:
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m -%s\n", $$1, $$2 }' ${MAKEFILE_LIST}

lint: ## Run Ruff linting (CI requires zero warnings)
	uv run ruff check ./ --fix

format: ## Auto-fix lint issues then apply Ruff formatter
	uv run ruff check ./ --fix
	uv run ruff format ./

run_tests: ## Run pytest
	uv run pytest -svvv --log-cli-level=DEBUG tests/

pre_push_test: format lint run_tests analyse_security ## Check code before push

build_wheel: ## Build wheel and sdist using uv
	uv build --wheel --sdist

push_wheel_to_repo: ## Publish package to Azure DevOps feed via uv
	uv build --wheel --sdist
	uv publish --publish-url https://pkgs.dev.azure.com/haut-ai/_packaging/haut-ai/pypi/upload/ --check-url https://pkgs.dev.azure.com/haut-ai/_packaging/haut-ai/pypi/simple/

install_dev_requirements: ## Install runtime + developer extras
	uv sync --group dev

install_requirements: ## Install runtime requirements only
	uv sync --no-group dev

install_all_requirements:  ## Install runtime + all optional groups
	uv sync --group dev
