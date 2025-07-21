-- Add migration script here
ALTER TABLE proof_config
    ADD COLUMN aggregate_block_count INT NOT NULL DEFAULT 1;
