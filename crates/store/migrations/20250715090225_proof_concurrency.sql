-- Add migration script here
DROP TABLE IF EXISTS `proof_concurrency`;
CREATE TABLE proof_concurrency
(
    `id`             INT NOT NULL DEFAULT 1,
    `concurrency`    INT NOT NULL DEFAULT 1,
    `updated_at`  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`id`)
);
