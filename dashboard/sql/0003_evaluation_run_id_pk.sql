-- Make run_id the sole primary key of `evaluation`.
--
-- The composite PK (run_id, version, evaluated_at) was over-defensive:
-- run_id is already a unique 8-hex UUID per agent run, and version is
-- fixed at run start (so it's functionally derivable from run_id).
-- evaluated_at — the CSV file mtime — was acting as a synthetic
-- disambiguator that caused the same logical eval to be inserted as
-- multiple rows whenever the CSV was rewritten by run_eval_rq1.py.
--
-- Migration steps (one transaction, ordered):
--   1. Collapse duplicates: keep only the latest evaluated_at per run_id.
--   2. Drop the old composite PK.
--   3. Add the new PK on run_id alone.

BEGIN;

-- 1. Delete older duplicates, keeping the freshest row per run_id.
DELETE FROM evaluation e
USING evaluation e2
WHERE e.run_id = e2.run_id
  AND (e.evaluated_at < e2.evaluated_at
       OR (e.evaluated_at = e2.evaluated_at AND e.ctid < e2.ctid));

-- 2. Drop the old composite primary key.
ALTER TABLE evaluation DROP CONSTRAINT evaluation_pkey;

-- 3. Promote run_id to the sole primary key.
ALTER TABLE evaluation ADD PRIMARY KEY (run_id);

COMMIT;
