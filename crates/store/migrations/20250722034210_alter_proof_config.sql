-- Add migration script here
ALTER TABLE proof_config
    ADD COLUMN start_aggregation_number INT NOT NULL DEFAULT 2;
