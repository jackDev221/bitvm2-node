-- Add migration script here
ALTER TABLE `instance`
    ADD COLUMN `is_bridge_in` BOOL NOT NULL DEFAULT 1;
ALTER TABLE instance
    RENAME COLUMN `pegin_request_tx_hash` TO `goat_tx_hash`;
ALTER TABLE `instance`
    RENAME COLUMN `pegin_request_height` TO `gaot_tx_height`;
ALTER TABLE `instance`
    RENAME COLUMN `pegin_prepare_txid` TO `btc_txid`;
ALTER TABLE `instance`
    RENAME COLUMN `pegin_prepare_height` TO `btc_height`;
ALTER TABLE `instance` DROP COLUMN `unsign_pegin_confirm_tx`;