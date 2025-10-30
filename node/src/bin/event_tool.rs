use anyhow::Result;
use bitvm2_noded::rpc_service::current_time_secs;
use bitvm2_noded::utils::strip_hex_prefix_owned;
use client::graphs::graph_query::BridgeInRequestEvent;
use serde::Deserialize;
use std::str::FromStr;
use std::{env, fs};
use store::localdb::LocalDB;
use store::{GoatTxProcessingStatus, GoatTxRecord, GoatTxType};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct Config {
    db_paths: Vec<String>,
    bridge_in_request_event: BridgeInRequestEvent,
}
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: event_tool <config.json>");
        std::process::exit(1);
    }

    let config_path = &args[1];
    println!("Using config: {}", config_path);

    let file_content = fs::read_to_string(config_path).expect("Failed to read config");
    let config: Config = serde_json::from_str(&file_content).expect("Failed to parse config");
    for db_file in &config.db_paths {
        let local_db = LocalDB::new(&format!("sqlite:{db_file}"), true).await;
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .upsert_goat_tx_record(&GoatTxRecord {
                instance_id: Uuid::from_str(&strip_hex_prefix_owned(
                    &config.bridge_in_request_event.instance_id,
                ))?,
                graph_id: Uuid::nil(),
                tx_type: GoatTxType::BridgeInRequest.to_string(),
                tx_hash: config.bridge_in_request_event.transaction_hash.clone(),
                height: config.bridge_in_request_event.block_number.parse::<i64>()?,
                is_local: false,
                processing_status: GoatTxProcessingStatus::Pending.to_string(),
                extra: Some(serde_json::to_string(&config.bridge_in_request_event)?),
                created_at: current_time_secs(),
            })
            .await.expect("fail to upsert goat tx record");
        println!("Successfully upserted goat tx record to db {db_file}");
    }
    Ok(())
}
