-- Rename modem column to device and add protocol column in tables:
--   - run
--   - sweep
--   - evaluation
--
-- For all existing rows, set the protocol value to 'fiveg'.
-- Rename run_modem_idx to run_device_idx.

BEGIN;

-- 1. Table: run
ALTER TABLE run RENAME COLUMN modem TO device;
ALTER TABLE run ADD COLUMN IF NOT EXISTS protocol text;
UPDATE run SET protocol = 'fiveg' WHERE protocol IS NULL;

-- Rename the index on run(modem) to run(device)
ALTER INDEX IF EXISTS run_modem_idx RENAME TO run_device_idx;

-- 2. Table: sweep
ALTER TABLE sweep RENAME COLUMN modem TO device;
ALTER TABLE sweep ADD COLUMN IF NOT EXISTS protocol text;
UPDATE sweep SET protocol = 'fiveg' WHERE protocol IS NULL;

-- 3. Table: evaluation
ALTER TABLE evaluation RENAME COLUMN modem TO device;
ALTER TABLE evaluation ADD COLUMN IF NOT EXISTS protocol text;
UPDATE evaluation SET protocol = 'fiveg' WHERE protocol IS NULL;

COMMIT;
