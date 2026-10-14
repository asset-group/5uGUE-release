-- Add turn.error — short reason tag for "stub" turn rows recorded when an
-- iteration bails on an error path (rate_limit, api_error, llm_error,
-- empty_response, empty_content) before completing normal work. Stub rows
-- carry phase="error" and zero deltas; they exist so total_turns (= turn row
-- count) reflects the turns actually attempted instead of only the completed
-- ones. NULL for all normal turns and for every historical run (forward-only;
-- existing runs are not backfilled).
ALTER TABLE turn
    ADD COLUMN IF NOT EXISTS error text;
