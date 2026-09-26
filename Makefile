SHELL := /bin/bash
UV := .bootstrap/bin/uv
PY := .venv/bin/python
CLI := .venv/bin/agentgate
export UV_CACHE_DIR := $(CURDIR)/.local/uv-cache
.PHONY: setup lint typecheck test test-integration policy-test up down demo attack-lab clean package audit
setup:
	./scripts/setup.sh
lint:
	.venv/bin/ruff check .
	.venv/bin/ruff format --check .
typecheck:
	.venv/bin/mypy
test:
	.venv/bin/pytest tests/unit -q
policy-test:
	$(CLI) policy test
up:
	./scripts/codespace-network.sh
	docker compose up --build --wait --wait-timeout 120 -d
down:
	docker compose down --remove-orphans
	./scripts/codespace-network.sh --remove
demo:
	$(PY) scripts/demo.py
attack-lab:
	.venv/bin/agentgate-redteam run
test-integration:
	.venv/bin/pytest tests/integration -q
package:
	$(UV) build
	.venv/bin/twine check dist/*
	$(PY) scripts/check_dist.py
audit:
	$(UV) export --frozen --no-dev --no-emit-project --format requirements-txt --output-file .local/requirements-audit.txt --quiet
	.venv/bin/pip-audit -r .local/requirements-audit.txt --disable-pip --cache-dir .local/audit-cache
clean:
	docker compose down --volumes --remove-orphans
	./scripts/codespace-network.sh --remove
	$(PY) scripts/clean.py
