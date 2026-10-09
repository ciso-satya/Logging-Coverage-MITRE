.PHONY: setup dev backend frontend build run test lint docker docker-run clean

PY := backend/.venv/bin/python

setup:            ## Create venv, install backend + frontend dependencies
	python3 -m venv backend/.venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -r backend/requirements-dev.txt
	cd frontend && npm install --no-audit --no-fund

build:            ## Build the production frontend bundle
	cd frontend && npm run build

run: build        ## Build the frontend and serve API + UI on http://localhost:8000
	cd backend && ../$(PY) -m uvicorn app.main:app --host 0.0.0.0 --port 8000

backend:          ## API only, with auto-reload (http://localhost:8000)
	cd backend && ../$(PY) -m uvicorn app.main:app --reload --port 8000

frontend:         ## Vite dev server with API proxy (http://localhost:5173)
	cd frontend && npm run dev

dev:              ## Run backend and frontend dev servers together
	$(MAKE) -j2 backend frontend

test:             ## Backend tests + frontend typecheck
	cd backend && ./.venv/bin/python -m pytest -q
	cd frontend && npm run typecheck

docker:           ## Build the Docker image
	docker build -t attack-logging-coverage .

docker-run:       ## Run with docker compose
	docker compose up --build

clean:
	rm -rf frontend/dist backend/.pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'
