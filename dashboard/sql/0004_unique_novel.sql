-- Add unique_novel — distinct crash_id count for tests where
-- crash_category == "fully_novel_crash". Backfilled for two historical
-- CSVs (eval_v3_20260429_145444.csv, eval_v3_20260430_184011.csv) by
-- scratchpad/backfill_eval_first_crash_metrics.py.
ALTER TABLE evaluation
    ADD COLUMN IF NOT EXISTS unique_novel int;
