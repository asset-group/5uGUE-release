"""FastAPI dashboard for visualizing fuzzing run snapshots.

Runs on the storage server at http://127.0.0.1:8000. The same FastAPI app exposes:

  GET  /api/runs               run list
  GET  /api/runs/{run_id}      run detail
  GET  /api/sweeps             sweep list
  GET  /api/sweeps/{sweep_id}  sweep detail
  GET  /healthz                DB liveness probe (returns 503 on PG outage)
  POST /ingest/...             worker → master ingest API (bearer-token gated)

The :8000 port is the only network surface. Postgres binds 127.0.0.1:5432
on the same host and is unreachable from the Tailnet.
"""

import os
import secrets

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles

from dashboard.data_loader import (
    load_run_list,
    load_run_data,
    list_runs,
    list_sweeps,
    load_sweep_data,
    list_reports,
    load_report_data,
)
from dashboard.db import healthcheck
from dashboard.ingest import router as ingest_router

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(title="Fuzz Run Dashboard")

_basic = HTTPBasic()


def _require_dashboard_login(
    creds: HTTPBasicCredentials = Depends(_basic),
) -> None:
    expected_user = os.environ.get("DASHBOARD_USERNAME", "admin")
    expected_pass = os.environ.get("DASHBOARD_PASSWORD", "")
    if not expected_pass:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="DASHBOARD_PASSWORD not configured on server",
        )
    user_ok = secrets.compare_digest(creds.username, expected_user)
    pass_ok = secrets.compare_digest(creds.password, expected_pass)
    if not (user_ok and pass_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )


app.mount(
    "/static",
    StaticFiles(directory=os.path.join(DASHBOARD_DIR, "static")),
    name="static",
)
app.include_router(ingest_router)


@app.get("/", dependencies=[Depends(_require_dashboard_login)])
def index():
    return FileResponse(os.path.join(DASHBOARD_DIR, "static", "index.html"))


@app.get("/healthz")
def healthz():
    if not healthcheck():
        raise HTTPException(status_code=503, detail="DB unavailable")
    return {"ok": True}


@app.get("/api/runs", dependencies=[Depends(_require_dashboard_login)])
def get_runs():
    return load_run_list()


@app.get("/api/runs/{run_id}", dependencies=[Depends(_require_dashboard_login)])
def get_run(run_id: str):
    result = load_run_data(run_id)
    if result is None:
        available = [r.get("run_id", "") for r in list_runs()]
        raise HTTPException(
            status_code=404, detail=f"Run '{run_id}' not found. Available: {available}"
        )
    return result


@app.get("/api/sweeps", dependencies=[Depends(_require_dashboard_login)])
def get_sweeps():
    return list_sweeps()


@app.get("/api/sweeps/{sweep_id}", dependencies=[Depends(_require_dashboard_login)])
def get_sweep(sweep_id: str):
    result = load_sweep_data(sweep_id)
    if result is None:
        available = [s.get("sweep_id", "") for s in list_sweeps()]
        raise HTTPException(
            status_code=404,
            detail=f"Sweep '{sweep_id}' not found. Available: {available}",
        )
    return result


@app.get("/api/reports", dependencies=[Depends(_require_dashboard_login)])
def get_reports():
    return list_reports()


@app.get("/api/reports/{eval_id}", dependencies=[Depends(_require_dashboard_login)])
def get_report(eval_id: str):
    result = load_report_data(eval_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Report '{eval_id}' not found")
    return result
