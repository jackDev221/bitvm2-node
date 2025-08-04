use crate::action::{GOATMessage, GOATMessageContent, recv_and_dispatch, send_to_peer};
use crate::client::{BTCClient, GOATClient};
use crate::env::get_local_node_info;
use crate::middleware::AllBehaviours;
use crate::middleware::swarm::{MessageHandler, TickMessageType};
use crate::utils::detect_heart_beat;
use bitvm2_lib::actors::Actor;
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm};
use store::ipfs::IPFS;
use store::localdb::LocalDB;

pub struct BitvmSwarmMessageHandler {
    pub local_db: LocalDB,
    pub btc_client: BTCClient,
    pub goat_client: GOATClient,
    pub ipfs: IPFS,
}
#[allow(clippy::too_many_arguments)]
pub async fn recv_and_dispatch_new(
    swarm: &mut Swarm<AllBehaviours>,
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    ipfs: &IPFS,
    actor: Actor,
    from_peer_id: PeerId,
    id: MessageId,
    message: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let a = recv_and_dispatch(
        swarm,
        local_db,
        btc_client,
        goat_client,
        ipfs,
        actor,
        from_peer_id,
        id,
        message,
    )
    .await;
    match a {
        Ok(_) => {}
        Err(e) => {
            println!("{e}")
        }
    }
    Ok(())
}

impl MessageHandler for BitvmSwarmMessageHandler {
    async fn recv_and_dispatch(
        &self,
        swarm: &mut Swarm<AllBehaviours>,
        actor: Actor,
        from_peer_id: PeerId,
        id: MessageId,
        message: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let result = recv_and_dispatch(
            swarm,
            &self.local_db,
            &self.btc_client,
            &self.goat_client,
            &self.ipfs,
            actor,
            from_peer_id,
            id,
            message,
        )
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                println!("{e}");
                Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))
            }
        }
    }

    async fn handle_tick_message(
        &self,
        swarm: &mut Swarm<AllBehaviours>,
        peer_id: PeerId,
        actor: Actor,
        msg_type: TickMessageType,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match msg_type {
            TickMessageType::HeartBeat => {
                match detect_heart_beat(swarm).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("detect_heart_beat: {e}");
                    }
                }
                tracing::debug!("Handling heartbeat tick message");
                Ok(())
            }
            TickMessageType::RegularlyAction => {
                tracing::debug!("Handling regular action tick message");
                let tick_data = serde_json::to_vec(&GOATMessage {
                    actor: actor.clone(),
                    content: "tick".as_bytes().to_vec(),
                })?;

                let result = recv_and_dispatch(
                    swarm,
                    &self.local_db,
                    &self.btc_client,
                    &self.goat_client,
                    &self.ipfs,
                    actor,
                    peer_id,
                    GOATMessage::default_message_id(),
                    &tick_data,
                )
                .await;
                match result {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        println!("{e}");
                        Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))
                    }
                }
            }
        }
    }

    async fn finish_subscribe_topic(
        &self,
        swarm: &mut Swarm<AllBehaviours>,
        _actor: Actor,
        topic: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if topic == Actor::All.to_string() {
            let message_content = GOATMessageContent::RequestNodeInfo(get_local_node_info());
            match send_to_peer(swarm, GOATMessage::from_typed(Actor::All, &message_content)?) {
                Ok(_) => {}
                Err(e) => {
                    println!("finish_subscribe_topic: send request NodeInfo {e}");
                }
            }
        }
        Ok(())
    }
}
