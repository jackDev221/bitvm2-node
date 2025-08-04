#![feature(trivial_bounds)]
use base64::Engine;
use bitvm2_lib::actors::Actor;
use bitvm2_noded::client::{BTCClient, GOATClient};
use bitvm2_noded::env::{
    self, ENV_PEER_KEY, check_node_info, get_ipfs_url, get_network, get_node_pubkey,
};
use clap::{Parser, Subcommand, command};
use libp2p::PeerId;
use libp2p_metrics::Registry;
use std::error::Error;
use std::sync::{Arc, Mutex};
use store::ipfs::IPFS;
use tracing_subscriber::EnvFilter;

use bitvm2_noded::rpc_service;
use bitvm2_noded::utils::{
    self, generate_local_key, run_watch_event_task, save_local_info,
    set_node_external_socket_addr_env,
};

use anyhow::Result;
use bitvm2_noded::middleware::swarm::{Bitvm2Swarm, Bitvm2SwarmConfig};
use bitvm2_noded::p2p_msg_handler::BitvmSwarmMessageHandler;
use futures::future;
use tokio::task::JoinHandle;

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
    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
    let mut metric_registry = Registry::default();
    let mut task_futures = vec![];
    let config = Bitvm2SwarmConfig::with_params(
        env::get_peer_key(),
        opt.p2p_port,
        opt.bootnodes,
        vec![
            Actor::Committee.to_string(),
            Actor::Challenger.to_string(),
            Actor::Operator.to_string(),
            Actor::Relayer.to_string(),
            Actor::All.to_string(),
        ],
    );
    let swarm = Bitvm2Swarm::new(config, &mut metric_registry)?;
    let peer_id_string = swarm.get_peer_id_string();
    let local_db = bitvm2_noded::client::create_local_db(&opt.db_path).await;
    let handler = BitvmSwarmMessageHandler {
        local_db: local_db.clone(),
        btc_client: BTCClient::new(None, env::get_network()),
        goat_client: GOATClient::new(env::goat_config_from_env().await, env::get_goat_network()),
        ipfs: IPFS::new(&get_ipfs_url()),
    };

    let actor_clone1 = actor.clone();
    let actor_clone2 = actor.clone();
    let local_db_clone1 = local_db.clone();
    let local_db_clone2 = local_db.clone();
    let opt_rpc_addr = opt.rpc_addr.clone();
    let peer_id_string_clone = peer_id_string.clone();
    let metric_registry_clone = Arc::new(Mutex::new(metric_registry));

    tracing::debug!("RPC service listening on {}", &opt.rpc_addr);
    if actor == Actor::Operator {
        set_node_external_socket_addr_env(&opt.rpc_addr).await?;
    }
    // validate node info
    check_node_info().await;
    save_local_info(&local_db).await;
    task_futures.push(tokio::spawn(async move {
        match rpc_service::serve(
            opt_rpc_addr,
            local_db_clone1,
            actor_clone1,
            peer_id_string_clone,
            metric_registry_clone,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("RPC service error: {}", e);
                "error".to_string()
            }
        }
    }));
    if actor == Actor::Relayer || actor == Actor::Operator {
        task_futures.push(tokio::spawn(async move {
            match run_watch_event_task(actor_clone2, local_db_clone2, 5).await {
                Ok(result) => result,
                Err(e) => {
                    tracing::error!("Watch event task error: {}", e);
                    "error".to_string()
                }
            }
        }));
    }

    let swarm_actor = actor.clone();
    task_futures.push(tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async { start_handle_swarm_msg_task(swarm_actor, swarm, handler).await })
        })
        .await;

        match result {
            Ok(swarm_result) => swarm_result,
            Err(e) => {
                tracing::error!("Swarm task spawn error: {}", e);
                "swarm_spawn_error".to_string()
            }
        }
    }));

    match future::select_all(task_futures).await {
        (Ok(tag), _, _) => {
            panic!("task:{tag:?} finished its run, while it wasn't expected to do it");
        }
        (Err(error), _, _) => {
            tracing::warn!("One of the tokio actors unexpectedly finished, shutting down");
            if error.is_panic() {
                std::panic::resume_unwind(error.into_panic());
            }
        }
    }

    Ok(())
}

pub async fn start_handle_swarm_msg_task(
    actor: Actor,
    mut swarm: Bitvm2Swarm,
    handler: BitvmSwarmMessageHandler,
) -> String {
    match swarm.run(actor, handler).await {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Swarm run error: {}", e);
            "swarm_error".to_string()
        }
    }
}

pub async fn wait_for_tasks(task_futures: Vec<JoinHandle<String>>) {
    match future::select_all(task_futures).await {
        (Ok(tag), _, _) => {
            panic!("task:{tag} finished its run, while it wasn't expected to do it");
        }
        (Err(error), _, _) => {
            tracing::warn!("One of the tokio actors unexpectedly finished, shutting down");
            if error.is_panic() {
                // Resume the panic on the main task
                std::panic::resume_unwind(error.into_panic());
            }
        }
    }
}
