-- Add migration script here

-- Add migration script here
DROP TABLE IF EXISTS `proof`;
CREATE TABLE proof
(
    `block_number` BIGINT NOT NULL DEFAULT 0,
    `proof`        TEXT   NOT NULL DEFAULT '',
    PRIMARY KEY (`block_number`)
);
