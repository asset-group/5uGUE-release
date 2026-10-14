-- Add per-session timing and crash-throughput metrics to the evaluation
-- table. Populated by rq_scripts/run_eval_rq1.py from the agent_metrics
-- JSONL last record. Older rows stay NULL — the source data isn't
-- recoverable for past runs and a backfill is not in scope.
ALTER TABLE evaluation
    ADD COLUMN IF NOT EXISTS unique_crashes               int,
    ADD COLUMN IF NOT EXISTS total_tests                  int,
    ADD COLUMN IF NOT EXISTS time_to_first_crash_seconds  real,
    ADD COLUMN IF NOT EXISTS tests_till_first_crash       int,
    ADD COLUMN IF NOT EXISTS total_session_time_seconds   real;
