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

verify_format: ## CI will call that to validate your code
	black --check "${PACKAGE_NAME}"

build_wheel: ## CI will call that to build your code
	python3 setup.py bdist_wheel

push_wheel_to_repo: ## Ci will call that to push your code to pypi repo
	twine upload -r "${WHEEL_REPO}" dist/*

run_tests: install_requirements download_weights ## CI can call that for you to run test on your code, feel free to change command if you want
	pytest -svvv tests/

analyse_security: ## Python security check, based on bandit (severity is medium or more}
	bandit -r -ll "${PACKAGE_NAME}"

pre_push_test: verify_format lint run_tests analyse_security## Call to pre-check your code before push

run_dev_container:
	docker-compose build
	docker-compose run lib-build bash
