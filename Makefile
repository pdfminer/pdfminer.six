##  Makefile (for maintenance purpose)

.PHONY: help
help:  ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

.PHONY: install
install:  ## Install all dependencies including dev dependencies using uv
	uv sync --all-groups --all-extras --no-install-project

.PHONY: format
format:  ## Format code with ruff
	uv run ruff format .

.PHONY: lint
lint:  ## Run ruff linter
	uv run ruff check .

.PHONY: lint-fix
lint-fix:  ## Run ruff linter and fix auto-fixable issues
	uv run ruff check --fix .

.PHONY: type-check
type-check:  ## Run mypy type checker
	uv run mypy --install-types --non-interactive --show-error-codes fuzzing pdfminer tools tests

.PHONY: test
test:  ## Run tests with pytest
	uv run pytest

.PHONY: check
check: install format lint-fix type-check test  ## Run all checks with auto-fixes (format, lint-fix, type-check, test)

.PHONY: docs
docs:  ## Build documentation
	uv run python -m sphinx -b html docs/source docs/build/html
	uv run python -m sphinx -b doctest docs/source docs/build/doctest

.PHONY: clean
clean:  ## Remove build artifacts, cache files, and temporary files
	rm -rf .venv/
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete
	find . -type f -name '*~' -delete

.DEFAULT_GOAL := help
