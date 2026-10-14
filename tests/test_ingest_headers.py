"""Regression test for the X-Host-Id / X-Session-Id header contract.

The ingest server reads identity from request headers (X-Host-Id,
X-Session-Id) — not from the JSON body — because envelopes get batched
and the headers drive FK stub creation. FastAPI maps a parameter named
`host_id` to the header `host-id` by default, NOT `X-Host-Id`. Without
an explicit `alias="X-Host-Id"` on the Header() default, the route
silently never sees the header workers send and rejects every batch
with a 400 ("X-Host-Id header required").

This caused a real outage during initial backfill on the storage
server — `scripts/backfill_to_db.py` failed on the very first
/ingest/runs/<run_id>/turns POST. The matching e2e suite
(test_ingest_e2e.py) only runs under testcontainers, which is not
installed in the default dev/CI environment, so the bug shipped.

This file inspects the route signatures directly so it runs without a
database. Cheap insurance against the alias getting dropped during a
refactor.
"""

from __future__ import annotations

import inspect
import os
import sys

import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(TESTS_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

fastapi = pytest.importorskip("fastapi")

from dashboard import ingest  # noqa: E402


HOST_ID_ROUTES = (
    "post_turns",
    "post_resources",
    "post_tests",
    "post_sweep_tests",
    "post_sweep_progress",
    "post_evaluations",
    "post_blob",
)
SESSION_ID_ROUTES = ("post_findings",)


def _header_default(fn, param_name):
    sig = inspect.signature(fn)
    assert param_name in sig.parameters, (
        f"{fn.__name__} has no '{param_name}' parameter — route signature changed"
    )
    return sig.parameters[param_name].default


@pytest.mark.parametrize("route_name", HOST_ID_ROUTES)
def test_host_id_header_uses_x_host_id_alias(route_name):
    fn = getattr(ingest, route_name)
    default = _header_default(fn, "host_id")
    assert isinstance(default, fastapi.params.Header), (
        f"{route_name}.host_id default is {type(default).__name__}, expected Header()"
    )
    assert default.alias == "X-Host-Id", (
        f"{route_name}.host_id missing alias='X-Host-Id' "
        f"(got alias={default.alias!r}). Without it, FastAPI maps the param "
        "to the 'host-id' header, NOT 'X-Host-Id', and every worker batch "
        "is rejected with 400."
    )


@pytest.mark.parametrize("route_name", SESSION_ID_ROUTES)
def test_session_id_header_uses_x_session_id_alias(route_name):
    fn = getattr(ingest, route_name)
    default = _header_default(fn, "session_id")
    assert isinstance(default, fastapi.params.Header), (
        f"{route_name}.session_id default is {type(default).__name__}, expected Header()"
    )
    assert default.alias == "X-Session-Id", (
        f"{route_name}.session_id missing alias='X-Session-Id'."
    )
