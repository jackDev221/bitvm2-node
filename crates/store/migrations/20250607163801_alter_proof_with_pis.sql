-- Add migration script here
ALTER TABLE proof_with_pis
    ADD COLUMN goat_block_number BIGINT NOT NULL DEFAULT 0;
ALTER TABLE proof_with_pis
    ADD COLUMN proof_cast BIGINT NOT NULL DEFAULT 0;