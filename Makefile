.DEFAULT_GOAL:=help
SHELL:=/bin/bash

.EXPORT_ALL_VARIABLES:
PYTHONPATH:=./

WHEEL_REPO:=haut_ai
PACKAGE_NAME:=hautai_vault

help:
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m -%s\n", $$1, $$2 }' ${MAKEFILE_LIST}

lint: ## Call to see output from flake8(must be 0 warnings to pass CI}
	flake8 "${PACKAGE_NAME}"

format: ## Call to format your code with black and isort
	isort "${PACKAGE_NAME}"
	black "${PACKAGE_NAME}"

run_tests: ## Run pytest
	pytest -svvv --log-cli-level=DEBUG tests/

analyse_security: ## Python security check, based on bandit (severity is medium or more}
	bandit -r -ll "${PACKAGE_NAME}"

pre_push_test: format lint run_tests analyse_security ## Check code before push
