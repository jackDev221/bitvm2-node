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
use tokio::signal;
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
    let mut task_handles: Vec<JoinHandle<String>> = vec![];
    // init bitvm2swarm
    let swarm = Bitvm2Swarm::new(
        Bitvm2SwarmConfig {
            local_key: env::get_peer_key(),
            p2p_port: opt.p2p_port,
            bootnodes: opt.bootnodes,
            topic_names: vec![
                Actor::Committee.to_string(),
                Actor::Challenger.to_string(),
                Actor::Operator.to_string(),
                Actor::Relayer.to_string(),
                Actor::All.to_string(),
            ],
            heartbeat_interval: env::HEARTBEAT_INTERVAL_SECOND,
            regular_task_interval: env::REGULAR_TASK_INTERVAL_SECOND,
        },
        &mut metric_registry,
    )?;
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
    task_handles.push(tokio::spawn(async move {
        rpc_service::serve(
            opt_rpc_addr,
            local_db_clone1,
            actor_clone1,
            peer_id_string_clone,
            metric_registry_clone,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::error!("RPC service error: {}", e);
            "error".to_string()
        })
    }));
    if actor == Actor::Relayer || actor == Actor::Operator {
        task_handles.push(tokio::spawn(async move {
            run_watch_event_task(actor_clone2, local_db_clone2, 5).await.unwrap_or_else(|e| {
                tracing::error!("Watch event task error: {}", e);
                "error".to_string()
            })
        }));
    }

    let swarm_actor = actor.clone();
    task_handles.push(tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async { start_handle_swarm_msg_task(swarm_actor, swarm, handler).await })
        })
        .await;

        result.unwrap_or_else(|e| {
            tracing::error!("Swarm task spawn error: {}", e);
            "swarm_spawn_error".to_string()
        })
    }));

    loop {
        tokio::select! {
            result = future::select_all(&mut task_handles), if !task_handles.is_empty() => {
                match result {
                    (Ok(tag), index, _) => {
                        tracing::warn!("Task {} finished unexpectedly, shutting down all tasks", tag);
                        task_handles.remove(index);
                        shutdown_tasks(task_handles).await;
                        break;
                    }
                    (Err(error), index, _) => {
                        tracing::warn!("A task finished unexpectedly: {}, shutting down all tasks", error);
                        // Remove the completed task
                        task_handles.remove(index);
                        if error.is_panic() {
                            shutdown_tasks(task_handles).await;
                            std::panic::resume_unwind(error.into_panic());
                        } else {
                            shutdown_tasks(task_handles).await;
                        }
                        break;
                    }
                }
            }
            _ = shutdown_signal() => {
                shutdown_tasks(task_handles).await;
                break;
            }
        }
    }

    Ok(())
}

/// Listen for shutdown signals (Ctrl+C, SIGTERM, etc.)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C signal, starting graceful shutdown...");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM signal, starting graceful shutdown...");
        },
    }
}

/// Gracefully shut down all tasks
async fn shutdown_tasks(task_handles: Vec<JoinHandle<String>>) {
    tracing::info!("Shutting down all tasks...");

    // Send abort signal to all tasks
    for handle in task_handles.iter() {
        handle.abort();
    }

    // Wait for all tasks to complete or be aborted
    for (index, handle) in task_handles.into_iter().enumerate() {
        match handle.await {
            Ok(tag) => {
                tracing::info!("Task {} (tag: {}) finished normally", index, tag);
            }
            Err(e) if e.is_cancelled() => {
                tracing::info!("Task {} was aborted", index);
            }
            Err(e) => {
                tracing::warn!("Task {} finished with error: {}", index, e);
            }
        }
    }

    tracing::info!("All tasks have been stopped");
}

pub async fn start_handle_swarm_msg_task(
    actor: Actor,
    mut swarm: Bitvm2Swarm,
    handler: BitvmSwarmMessageHandler,
) -> String {
    swarm.run(actor, handler).await.unwrap_or_else(|e| {
        tracing::error!("Swarm run error: {}", e);
        "swarm_error".to_string()
    })
}
