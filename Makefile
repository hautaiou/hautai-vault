.DEFAULT_GOAL:=help
SHELL:=/bin/bash

.EXPORT_ALL_VARIABLES:
PYTHONPATH:=./

WHEEL_REPO:=haut_ai
PACKAGE_NAME:=hautai_vault

help:
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m -%s\n", $$1, $$2 }' ${MAKEFILE_LIST}

lint: ## Call to see output from flake8(must be 0 warnings to pass CI}
	ruff check ./ --fix

format: ## Call to format your code with black and isort
	ruff check ./ --fix
	ruff format ./

run_tests: ## Run pytest
	pytest -svvv --log-cli-level=DEBUG tests/

pre_push_test: format lint run_tests analyse_security ## Check code before push

build_wheel: ## CI will call that to build your code
	poetry build --skip-existing

push_wheel_to_repo: ## Ci will call that to push your code to pypi repo
	poetry publish --build --skip-existing -r haut_ai_publish -vvv --no-interaction

install_dev_requirements: ## Install dev requirements
	poetry install --group dev

install_requirements: ## Install requirements
	poety install --exclude dev

install_all_requirements:  ## Install all requirements
	poetry install
