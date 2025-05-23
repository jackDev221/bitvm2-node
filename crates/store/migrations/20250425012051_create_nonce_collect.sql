-- Add migration script here
DROP TABLE IF EXISTS `nonce_collect`;
CREATE TABLE nonce_collect
(
    `instance_id`      TEXT   NOT NULL,
    `graph_id`         TEXT   NOT NULL,
    `nonces`           TEXT   NOT NULL DEFAULT '',
    `committee_pubkey` TEXT   NOT NULL DEFAULT '',
    `partial_sigs`     TEXT   NOT NULL DEFAULT '',
    `created_at`       BIGINT NOT NULL DEFAULT 0,
    `updated_at`       BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`instance_id`, `graph_id`)
);
