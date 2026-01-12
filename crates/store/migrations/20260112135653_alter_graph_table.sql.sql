-- Add migration script here
ALTER TABLE `graph`
    ADD COLUMN `local_watchtower_challenge_txid` TEXT;
