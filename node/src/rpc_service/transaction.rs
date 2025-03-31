use std::collections::HashMap;
use axum::extract::State;
use axum::{Json, Router, http::StatusCode};
use bitvm2_lib::actors::Actor;
use serde::{Deserialize, Serialize};
use std::default::Default;
use std::sync::Arc;
use store::localdb::LocalDB;
use store::{Covenant, Node, Transaction};
use tracing_subscriber::fmt::time;

// the input to our `create_user` handler
#[derive(Deserialize)]
pub struct TransactionParams {
    pub bridge_path: String,
    pub pegin_txid: Option<String>,
}

#[axum::debug_handler]
pub async fn create_transaction(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<TransactionParams>,
) -> (StatusCode, Json<Transaction>) {
    // insert your application logic here
    let tx = Transaction {
        bridge_path: payload.bridge_path,
    };
    local_db.create_transaction(tx.clone()).await;
    (StatusCode::OK, Json(tx))
}
#[axum::debug_handler]
pub async fn get_transaction(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<TransactionParams>,
) -> (StatusCode, Json<Transaction>) {
    // insert your application logic here
    let tx = Transaction {
        bridge_path: payload.bridge_path,
        ..Default::default()
    };
    local_db.get_transaction(tx.clone()).await;
    (StatusCode::OK, Json(tx))
}

#[derive(Deserialize)]
pub struct UTXO {
    txid: String,
    vout: u32,
    //.. others
}

/// bridge-in: step1 & step2.1
#[derive(Deserialize)]
pub struct BridgeInTransactionPrepare {
    /// UUID
    pub instance_id: String,
    /// testnet3 | mainnet
    pub network: String,
    /// pBTC <-> tBTC | BTC
    pub bridge_path: String,
    pub amount: u64,
    pub fee_rate: u64,
    pub utxo: Vec<UTXO>,

    // address
    pub sender: String,
    pub receiver: String,
}

pub struct BridgeInTransactionPrepareResponse {
    status: StatusCode,
}

/// bridge-in step2.2

/// deps: TransactionPrepare
///  handler: operator
pub struct GraphGenerate {
    pub instance_id: String,
    // UUID
    pub graph_id: String,

    //calculate staking amount according to the peg-in amount
}

// UI can go next(step2.3) once one operator responds
pub struct GraphGenerateResponse {
    pub instance_id: String,
    pub graph_id: String,
    // unsigned_txns, operator signature, this steps ask operator to publish unsigned txns
    pub graph_ipfs_unsigned_txns: String,
    pub graph_ipfs_operator_sig: String,
}

/// bridge-in step 2.3

/// handler: federation
pub struct GraphPresign {
    pub instance_id: String,
    pub graph_id: String,
    pub graph_ipfs_url: String,
}

// Federation publish txn signatures in ipfs url
pub struct GraphPresignResponse {
    pub instance_id: String,
    pub graph_id: String,
    pub graph_ipfs_federation_sig: String,
}

pub struct GraphPresignCheck {
    pub instance_id: String,
    // get graph_id from nodes' database,
}

pub struct GraphPresignCheckResponse {
    pub instance_id: String,
    pub instace_status: String,
    pub graph_status: HashMap<String, String>,
    pub tx: Option<Transaction>,
}

/// bridge-in: step3

/// handler: relayer
pub struct PegBTCMint {
    pub instance_id: String,
    pub graph_id: Vec<String>,
    pub pegin_txid: String,
    // TODO: https://github.com/GOATNetwork/bitvm2-L2-contracts/blob/main/contracts/Gateway.sol#L43
}

pub struct PegBTCMintResponse {
    // 200: success,
    pub status_code: http::StatusCode,
}


/// bridge-out step2
pub struct BridgeOutTransactionPrepare {
    pub instance_id: String,
    // GOAT txid
    pub pegout_txid: String,
    // For double check with operator selected in peg out txn
    pub operator: String,
}

pub struct BridgeOutTransactionPrepareResponse {
    pub instance_id: String,
    pub btc_hashed_timelock_utxo: UTXO,
    /// BTC address
    pub operator_refund_address: String,
}

// handler: Federation
pub struct BridgeOutUserClaimRequest {
    pub instance_id: String,
    // hex
    pub pegout_txid: String,
    pub signed_claim_txn: String,
}

pub struct BridgeOutUserClaimResponse {
    pub instance_id: String,
    pub claim_txid: String,
}


/// get tx detail

pub struct InstanceListRequest {
    pub user_address: String,
}

pub struct InstanceListResponse {
    //                               // instance_id -> (txid, bridge_path)
    pub instances: Vec<Instance>, // HashMap<String, (String, String)>
}

pub struct Instance {
    pub instance_id: String,
    pub bridge_path: String,
    pub from: String,
    pub to: String,

    // in sat
    pub amount: u64,
    pub created_at: u64,

    // updating time
    pub eta_at: u64,


    // TODO: need to define
    pub status: u32,

    pub goat_txid: String,
    pub btc_txid: String,
}

pub struct InstanceGetRequest {
    pub instance_id: String,
}

pub struct InstanceGetResponse {
    pub instance: Instance,
}