-- Add migration script here
DROP TABLE IF EXISTS `contract`;
CREATE TABLE contract
(
    `id`          INTEGER PRIMARY KEY,
    `addr`        TEXT   NOT NULL DEFAULT '',
    `gap`         BIGINT NOT NULL DEFAULT 0, 
    `from_height` BIGINT NOT NULL DEFAULT 0,
    `extra`       TEXT,
    `created_at`  BIGINT NOT NULL DEFAULT 0,
    `updated_at`  BIGINT NOT NULL DEFAULT 0,
    UNIQUE (addr)
);

