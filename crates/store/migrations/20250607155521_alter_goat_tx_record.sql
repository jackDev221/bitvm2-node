-- Add migration script here
ALTER TABLE goat_tx_record
    ADD COLUMN proof_status TEXT NOT NULL DEFAULT 'NoNeed';
