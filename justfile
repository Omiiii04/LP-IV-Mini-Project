default: test

setup:
    python -m venv .venv
    python -m pip install --upgrade pip
    pip install -r requirements-dev.txt

run:
    flask run --debug --port 5000

test:
    pytest --cov=services --cov-report=term-missing

seed:
    flask seed --reset

lint:
    ruff check .

format:
    ruff format .

check: lint test
