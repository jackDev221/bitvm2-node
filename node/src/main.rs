#![feature(trivial_bounds)]
use base64::Engine;
use clap::{Parser, Subcommand, command};
use libp2p::PeerId;
use libp2p_metrics::Registry;
use std::sync::{Arc, Mutex};
use std::error::Error;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

use bitvm2_lib::actors::Actor;

use bitvm2_noded::env::{
    self, ENV_PEER_KEY,  get_network,
    get_node_pubkey,
};
use bitvm2_noded::rpc_service;
use bitvm2_noded::utils::{
    self, generate_local_key, run_watch_event_task, save_local_info,
};

use anyhow::Result;
use futures::future;
use store::localdb::LocalDB;
use tokio::sync::watch;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    /// Setup the bootnode p2p port
    #[arg(long, default_value = "0")]
    p2p_port: u16,

    /// Local RPC service address
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub rpc_addr: String,

    /// Local Sqlite database file path
    #[arg(long, default_value = "/tmp/bitvm2-node.db")]
    pub db_path: String,

    /// Peer nodes as the bootnodes
    #[arg(long)]
    bootnodes: Vec<String>,

    /// Metric endpoint path.
    #[arg(long, default_value = "/metrics")]
    metrics_path: String,

    /// Whether to run the libp2p Kademlia protocol and join the BitVM2 DHT.
    #[arg(long, default_value = "true")]
    enable_kademlia: bool,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Key(KeyArg),
    Peer(PeerArg),
}

#[derive(Parser, Debug, Clone)]
struct KeyArg {
    #[arg(long, default_value = "ed25519")]
    kind: String,
    #[command(subcommand)]
    cmd: KeyCommands,
}

#[derive(Parser, Debug, Clone)]
struct PeerArg {
    #[clap(subcommand)]
    peer_cmd: PeerCommands,
}

#[derive(Parser, Debug, Clone)]
enum PeerCommands {
    GetPeers {
        #[clap(long)]
        peer_id: Option<PeerId>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum KeyCommands {
    /// Generate peer secret key and peer id
    Peer,
    /// Generate the funding address with the Hex-Encoded private key in .env
    FundingAddress,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::dotenv().ok();
    let actor = env::get_actor();
    let opt = Opts::parse();
    if let Some(Commands::Key(key_arg)) = opt.cmd {
        match key_arg.cmd {
            KeyCommands::Peer => {
                let local_key = generate_local_key();
                let base64_key = base64::engine::general_purpose::STANDARD
                    .encode(&local_key.to_protobuf_encoding()?);
                let peer_id = local_key.public().to_peer_id().to_string();
                println!("{ENV_PEER_KEY}={base64_key}");
                println!("PEER_ID={peer_id}");
            }
            KeyCommands::FundingAddress => {
                let public_key = get_node_pubkey()?;
                let p2wsh_addr = utils::node_p2wsh_address(get_network(), &public_key);
                println!("Funding P2WSH address (for operator and challenger): {p2wsh_addr}");
            }
        }
        return Ok(());
    }
    // load role
    let local_key = env::get_peer_key();
    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
    let local_key = libp2p::identity::Keypair::from_protobuf_encoding(&Zeroizing::new(
        base64::engine::general_purpose::STANDARD.decode(local_key)?,
    ))?;
    tracing::debug!("RPC service listening on {}", &opt.rpc_addr);
    let rpc_addr = opt.rpc_addr.clone();
    let db_path = opt.db_path.clone();
    let local_db = bitvm2_noded::client::create_local_db(&db_path).await;
    save_local_info(&local_db).await;
    let (stop_signal_sender, mut stop_signal_receiver) = watch::channel("".to_string());

    tokio::spawn(run_tasks(
        actor.clone(),
        rpc_addr,
        local_db.clone(),
        local_key.public().to_peer_id().to_string(),
        Arc::new(Mutex::new(Registry::default())),
        stop_signal_sender,
    ));
    let _= stop_signal_receiver.changed().await;
    tracing::error!("receive stop signal");
    Ok(())
}

pub async fn run_tasks(
    actor: Actor,
    rpc_addr: String,
    local_db: LocalDB,
    peer_id: String,
    registry: Arc<Mutex<Registry>>,
    stop_signal_sender: watch::Sender<String>,
) {
    let mut tasks = vec![];
    tasks.push(tokio::spawn(rpc_service::serve(
        rpc_addr,
        local_db.clone(),
        actor.clone(),
        peer_id,
        registry,
    )));
    if actor == Actor::Relayer || actor == Actor::Operator {
        tasks.push(tokio::spawn(run_watch_event_task(actor.clone(), local_db.clone(), 5)));
    }
    // if actor == Actor::Operator {
    //     tasks.push(tokio::spawn(run_gen_groth16_proof_task(local_db.clone(), 5)));
    // }
    let msg = format!("One task stop. detail: {:?}", future::select_all(tasks).await);
    _ = stop_signal_sender.send(msg);
}
