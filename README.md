# Digital Forensics Toolkit

DFT is a single-user academic workbench for organizing digital evidence, checking stored-file integrity, reviewing security logs, and generating case reports. It is intended for triage and demonstration; rule matches are leads, not conclusions.

## What it does

- **Case records:** Track an investigator, scope, status, and activity history for each case.
- **Evidence register:** Store evidence under generated storage names and record a streaming SHA-256 baseline. Verify before download and inspect a bounded text or hex preview.
- **Security log review:** Apply deterministic rules to supported log files and preserve structured findings with their source events.
- **Case reports:** Export PDF, JSON, or CSV reports. Record the SHA-256 digest of each generated report in the case ledger.
- **Synthetic showcase:** Load three prepared cases with clean and flagged logs, intact evidence, and one deliberately altered file for an integrity-check walkthrough.

## Local setup

Python 3.12 or newer is recommended.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

Run the complete test suite, reset the synthetic cases, and start the app with one command:

```powershell
make showcase
```

Or use `just showcase`. Open `http://127.0.0.1:5000`. The landing page and workstation both have a **Reload full showcase** action. It rebuilds the prepared cases, evidence, logs, and reports while preserving non-demo cases. For clean repeatable demo data, use the command; it resets the prepared cases before starting the server.

To run individual steps:

```powershell
.venv\Scripts\python.exe -m pytest
.venv\Scripts\flask.exe --app app seed --reset
.venv\Scripts\python.exe app.py
```

## Run in Docker

Build and start the container locally (Docker Desktop must be running):

```powershell
docker build -t dft .
docker run --rm -p 5000:10000 -e "SECRET_KEY=local-demo-secret-change-this" -e "AUTO_SEED_DEMO=true" -v dft-data:/var/data dft
```

Open `http://127.0.0.1:5000`. The named volume keeps the SQLite ledger and uploaded evidence between container restarts.

## Render deployment

The included `render.yaml` deploys the Docker image as a Render Blueprint, creates a health check and 1 GB persistent disk, generates `SECRET_KEY`, and seeds the synthetic showcase when the database is empty. Deploy it like this:

1. Commit and push the project to a GitHub repository.
2. In Render, choose **New** → **Blueprint**, connect that repository, and select **Apply** after Render reads `render.yaml`.
3. Choose the configured paid web-service plan. The disk is required for the SQLite database and uploaded evidence; Render's free web services do not support persistent disks.
4. Wait for deployment, then check `https://<your-service>.onrender.com/health` returns `{"status":"ok"}`.
5. Open the service URL and use **Reload full synthetic showcase** to run the walkthrough.

The service has no login and is publicly reachable. Use only synthetic data; do not upload real case evidence. Its disk is single-instance storage, not a multi-user or production evidence-vault design.

## Scope and limitations

- DFT has no login, roles, or multi-user isolation.
- Stored-file hashes detect changes to the registered bytes, but do not prevent an administrator from changing both the database and file.
- Log rules are deterministic pattern checks. Findings require analyst review and are not proof of intent.
- The app analyzes uploaded log files and ordinary evidence previews; it does not mount or analyze disk images.
- Do not use the prototype as a production evidence vault or submit real sensitive evidence to a public deployment.

## Tests and checks

```powershell
.venv\Scripts\python.exe -m pytest
.venv\Scripts\ruff.exe check .
```

Playwright smoke coverage checks the landing page, workstation, case workflow, reduced-motion behavior, and horizontal overflow at phone, tablet, and desktop widths.

## Project map

- `app.py` — Flask application factory, routes, upload controls, and CLI commands.
- `models.py` — case, evidence, log-analysis, report, and activity records.
- `services/` — hashing, safe evidence preview, deterministic log rules, reporting, and demo seeding.
- `templates/`, `static/` — server-rendered interface and self-hosted assets.
- `sample_data/` — synthetic files used by tests and the showcase.
- `Dockerfile`, `docker-entrypoint.sh`, `.dockerignore` — container build and runtime setup.
- `render.yaml` — Render Docker Blueprint and persistent-storage configuration.
