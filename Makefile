.PHONY: setup run test seed lint format check clean

PYTHON ?= python
VENV_DIR ?= .venv

ifeq ($(OS),Windows_NT)
    VENV_BIN = $(VENV_DIR)/Scripts
    PYTHON_BIN = $(VENV_BIN)/python.exe
    PYTEST_BIN = $(VENV_BIN)/pytest.exe
    FLASK_BIN = $(VENV_BIN)/flask.exe
    RUFF_BIN = $(VENV_BIN)/ruff.exe
else
    VENV_BIN = $(VENV_DIR)/bin
    PYTHON_BIN = $(VENV_BIN)/python
    PYTEST_BIN = $(VENV_BIN)/pytest
    FLASK_BIN = $(VENV_BIN)/flask
    RUFF_BIN = $(VENV_BIN)/ruff
endif

setup:
	$(PYTHON) -m venv $(VENV_DIR)
	$(PYTHON_BIN) -m pip install --upgrade pip
	$(PYTHON_BIN) -m pip install -r requirements-dev.txt

run:
	$(FLASK_BIN) run --debug --port 5000

test:
	$(PYTEST_BIN) --cov=services --cov-report=term-missing

seed:
	$(FLASK_BIN) seed --reset

lint:
	$(RUFF_BIN) check .

format:
	$(RUFF_BIN) format .

check: lint test
