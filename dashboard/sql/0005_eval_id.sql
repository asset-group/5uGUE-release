-- Add eval_id grouping key to the evaluation table. One eval_id per
-- multi-run CSV produced by rq_scripts/run_eval_rq1.py; all N rows of
-- one CSV share the value. Existing rows get NULL and are filled by
-- scripts/backfill_eval_id.py. Format is uuid.uuid4().hex (32 hex
-- chars) — distinguishes from run_id/sweep_id (8 hex chars).
ALTER TABLE evaluation
    ADD COLUMN IF NOT EXISTS eval_id text;

ALTER TABLE evaluation
    DROP CONSTRAINT IF EXISTS evaluation_eval_id_format;

ALTER TABLE evaluation
    ADD CONSTRAINT evaluation_eval_id_format
    CHECK (eval_id IS NULL OR eval_id ~ '^[0-9a-f]{32}$');

CREATE INDEX IF NOT EXISTS evaluation_eval_id_idx ON evaluation (eval_id);
