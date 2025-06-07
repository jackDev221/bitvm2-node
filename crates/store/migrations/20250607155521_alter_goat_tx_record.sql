-- Add migration script here
ALTER TABLE goat_tx_record
    ADD COLUMN prove_status TEXT NOT NULL DEFAULT 'NoNeed';
