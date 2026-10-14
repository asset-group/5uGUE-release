-- Initial schema for the Postgres-backed ingest + dashboard pipeline.
--
-- All timestamps are timestamptz and stored in UTC. Wherever the dashboard
-- currently formats from a literal manifest string, a sibling raw-string
-- column (`*_str`) is kept so display output is byte-identical to the
-- file-backed dashboard. Conversion uses AGENT_TIMEZONE (default UTC) to
-- interpret %Y%m%d-%H%M%S / %Y-%m-%dT%H:%M:%S — see dashboard/db.py:to_ts().
--
-- Streaming semantics: every ingest is INSERT … ON CONFLICT (pk) DO UPDATE.
-- FK targets (run, sweep) auto-create as `status='partial'` stubs when a
-- child event arrives first; the real start event later UPSERTs full fields.
-- Stub columns must therefore be NULLABLE (or have defaults).

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migration (
    filename    text PRIMARY KEY,
    applied_at  timestamptz NOT NULL DEFAULT now()
);

-- ─── host ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS host (
    host_id     text PRIMARY KEY,
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT host_id_charset CHECK (host_id ~ '^[A-Za-z0-9._-]+$')
);

-- ─── run ───────────────────────────────────────────────────────────────────
-- run_id is _compute_run_id output: 8 lowercase hex chars.
CREATE TABLE IF NOT EXISTS run (
    run_id                       char(8) PRIMARY KEY,
    session_id                   text,
    host_id                      text NOT NULL REFERENCES host(host_id),
    modem                        text,
    version                      text,
    model                        text,
    max_turns                    int,
    timestamp_str                text,         -- raw manifest "%Y%m%d-%H%M%S"
    started_at                   timestamptz,  -- parsed via AGENT_TIMEZONE
    ended_at                     timestamptz,
    status                       text NOT NULL DEFAULT 'partial',
    app_log_path                 text,
    runtime_log_path             text,
    metrics_png_path             text,
    resource_metrics_png_path    text,
    final_total_crashes          int,
    final_unique_crashes         int,
    final_publicly_known         int,
    final_non_publicly_known     int,
    final_fully_novel            int,
    total_input_tokens           bigint,
    total_output_tokens          bigint,
    ingested_at                  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT run_id_format CHECK (run_id ~ '^[a-z0-9]{8}$')
);

CREATE INDEX IF NOT EXISTS run_host_started_idx ON run (host_id, started_at DESC);
CREATE INDEX IF NOT EXISTS run_started_idx      ON run (started_at DESC);
CREATE INDEX IF NOT EXISTS run_modem_idx        ON run (modem);
CREATE INDEX IF NOT EXISTS run_version_idx      ON run (version);
CREATE INDEX IF NOT EXISTS run_session_id_idx   ON run (session_id);

-- ─── turn ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS turn (
    run_id                          char(8) NOT NULL REFERENCES run(run_id),
    turn                            int NOT NULL,
    ts                              timestamptz NOT NULL,
    tools_called                    jsonb,
    tool_call_count                 int,
    tool_counts                     jsonb,
    input_tokens                    int,
    output_tokens                   int,
    cumulative_input_tokens         bigint,
    cumulative_output_tokens        bigint,
    turn_crashes                    int,
    turn_publicly_known             int,
    turn_non_publicly_known         int,
    turn_fully_novel                int,
    cumulative_crashes              int,
    cumulative_publicly_known       int,
    cumulative_non_publicly_known   int,
    cumulative_fully_novel          int,
    session_unique_crashes          int,
    phase                           text,
    PRIMARY KEY (run_id, turn)
);

-- ─── resource_sample ───────────────────────────────────────────────────────
-- Field set mirrors resource_monitor.py:74-84 exactly.
CREATE TABLE IF NOT EXISTS resource_sample (
    run_id              char(8) NOT NULL REFERENCES run(run_id),
    ts                  timestamptz NOT NULL,
    turn                int,
    cpu_percent         real,
    mem_rss_mb          real,
    mem_system_percent  real,
    disk_read_mb        real,
    disk_write_mb       real,
    net_sent_mb         real,
    net_recv_mb         real,
    event               text,
    metadata            jsonb,
    PRIMARY KEY (run_id, ts)
);

-- ─── test ──────────────────────────────────────────────────────────────────
-- One row per executed test. The `crash` view filters down for the dashboard.
CREATE TABLE IF NOT EXISTS test (
    run_id                      char(8) NOT NULL REFERENCES run(run_id),
    test_id                     text NOT NULL,
    session_id                  text,
    exploit_name                text,
    exploit_code                text,
    exploit_hash                text,
    fuzz_description            text,
    crash                       boolean,
    crash_category              text,
    crash_id                    text,
    new_states                  int,
    new_transitions             int,
    compile_success             boolean,
    execution_time_seconds      real,
    mutation_count              int,
    mutation_parse_warnings     jsonb,
    total_packets               int,
    timestamp_str               text,
    ts                          timestamptz,
    PRIMARY KEY (run_id, test_id)
);

CREATE INDEX IF NOT EXISTS test_crash_idx    ON test (crash) WHERE crash;
CREATE INDEX IF NOT EXISTS test_crash_id_idx ON test (crash_id) WHERE crash_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS test_session_idx  ON test (session_id);

CREATE OR REPLACE VIEW crash AS
    SELECT * FROM test WHERE crash IS TRUE;

-- ─── sweep ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sweep (
    sweep_id            char(8) PRIMARY KEY,
    host_id             text NOT NULL REFERENCES host(host_id),
    modem               text,
    profile             text,
    filters             jsonb,
    offset_range        int4range,
    offsets_per_filter  int,
    offset_strategy     text,
    "values"            jsonb,
    values_hex          jsonb,
    total_combinations  int,
    exploit_timeout     int,
    retry_of            char(8) REFERENCES sweep(sweep_id),
    retry_depth         int,
    start_time_str      text,
    started_at          timestamptz,
    ended_at            timestamptz,
    status              text NOT NULL DEFAULT 'partial',
    ingested_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sweep_id_format CHECK (sweep_id ~ '^[a-z0-9]{8}$')
);

CREATE INDEX IF NOT EXISTS sweep_host_started_idx ON sweep (host_id, started_at DESC);
CREATE INDEX IF NOT EXISTS sweep_retry_of_idx     ON sweep (retry_of);

-- ─── sweep_test ────────────────────────────────────────────────────────────
-- "values"/"offset" quoted because both are reserved words.
CREATE TABLE IF NOT EXISTS sweep_test (
    sweep_id                char(8) NOT NULL REFERENCES sweep(sweep_id),
    test_num                int NOT NULL,
    filter                  text,
    "offset"                int,
    value                   int,
    value_hex               text,
    crash                   boolean,
    crash_id                text,
    crash_category          text,
    compile_success         boolean,
    compile_error           text,
    execution_time_seconds  real,
    mutation_count          int,
    total_packets           int,
    timestamp_str           text,
    ts                      timestamptz,
    PRIMARY KEY (sweep_id, test_num)
);

CREATE UNIQUE INDEX IF NOT EXISTS sweep_test_combo_idx
    ON sweep_test (sweep_id, filter, "offset", value);
CREATE INDEX IF NOT EXISTS sweep_test_crash_idx
    ON sweep_test (sweep_id) WHERE crash IS TRUE;

-- ─── sweep_progress ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sweep_progress (
    sweep_id            char(8) NOT NULL REFERENCES sweep(sweep_id),
    ts                  timestamptz NOT NULL,
    timestamp_str       text,
    tests_completed     int,
    tests_total         int,
    tests_remaining     int,
    crashes_found       int,
    unique_crash_ids    int,
    elapsed_seconds     real,
    avg_seconds_per_test real,
    eta_seconds         real,
    eta_hours           real,
    status              text,
    PRIMARY KEY (sweep_id, ts)
);

-- ─── evaluation ────────────────────────────────────────────────────────────
-- One row per CSV row written by rq_scripts/run_eval_rq1.py:write_csv.
CREATE TABLE IF NOT EXISTS evaluation (
    run_id                      char(8) NOT NULL REFERENCES run(run_id),
    version                     text NOT NULL,
    evaluated_at                timestamptz NOT NULL,
    session_id                  text,
    model                       text,
    modem                       text,
    max_turns                   int,
    actual_turns                int,
    rq_max_score                int,
    rq_max_level                text,
    rq_mean_score               real,
    publicly_known_crashes      int,
    non_publicly_known_crashes  int,
    fully_novel_crashes         int,
    total_crashes               int,
    total_input_tokens          bigint,
    total_output_tokens         bigint,
    unique_crashes               int,
    unique_novel                 int,
    total_tests                  int,
    time_to_first_crash_seconds  real,
    tests_till_first_crash       int,
    total_session_time_seconds   real,
    source_csv_path             text,
    PRIMARY KEY (run_id)
);

-- ─── session_finding ───────────────────────────────────────────────────────
-- Findings tied to a session (KnowledgeBase.save_finding). Run linkage is
-- query-time via JOIN run ON run.session_id = session_finding.session_id —
-- intentionally no FK to run, since a session can outlive a single run.
CREATE TABLE IF NOT EXISTS session_finding (
    session_id      text NOT NULL,
    finding_id      int  NOT NULL,
    type            text,
    description     text,
    related_tests   jsonb,
    tags            jsonb,
    source_url      text,
    dedup_key       text,
    timestamp_str   text,
    ts              timestamptz NOT NULL,
    PRIMARY KEY (session_id, finding_id)
);

CREATE INDEX IF NOT EXISTS session_finding_session_idx ON session_finding (session_id);

-- ─── global_finding ────────────────────────────────────────────────────────
-- Cross-session promoted findings. dedup_key is the natural key — workers
-- that emit the same key collapse into one row.
CREATE TABLE IF NOT EXISTS global_finding (
    dedup_key       text PRIMARY KEY,
    description     text,
    tags            jsonb,
    source_session  text,
    timestamp_str   text,
    ts              timestamptz NOT NULL
);

-- ─── session_strategy ──────────────────────────────────────────────────────
-- KnowledgeBase.update_strategy() rewrites the entire strategy.md each call.
CREATE TABLE IF NOT EXISTS session_strategy (
    session_id   text PRIMARY KEY,
    host_id      text REFERENCES host(host_id),
    text         text,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- ─── run_blob ──────────────────────────────────────────────────────────────
-- File paths to large artifacts that stay on the rsynced filesystem
-- (app_log, runtime_log, metrics_png, resource_metrics_png).
CREATE TABLE IF NOT EXISTS run_blob (
    run_id  char(8) NOT NULL REFERENCES run(run_id),
    kind    text NOT NULL,
    path    text NOT NULL,
    PRIMARY KEY (run_id, kind),
    CONSTRAINT run_blob_kind CHECK (kind IN
        ('app_log', 'runtime_log', 'metrics_png', 'resource_metrics_png'))
);

COMMIT;
