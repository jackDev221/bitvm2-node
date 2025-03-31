use std::string::String;
use rand::RngCore;
use secp256k1::Secp256k1;
use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
};

use futures::StreamExt;
use libp2p::{
    core::{Multiaddr, multiaddr::Protocol},
    identify, identity, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use tracing_subscriber::EnvFilter;
use musig2::{
    AggNonce, SecNonce,
    CompactSignature, FirstRound, PartialSignature, PubNonce, SecNonceSpices, SecondRound,
};
use musig2::KeyAggContext;

pub fn generate_local_key() -> identity::Keypair {
    identity::Keypair::generate_ed25519()
}

// all key pair can be represented by identity::keypair
pub fn generate_musig2_key() -> secp256k1::Keypair {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
    secp256k1::Keypair::from_secret_key(&secp, &secret_key)
}

pub fn musig2_first_round(key_agg_ctx: KeyAggContext, signer_index: usize, message: &str, seckey: &secp256k1::SecretKey) -> FirstRound {
    let mut nonce_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce_seed);

    let mut first_round = FirstRound::new(
        key_agg_ctx,
        nonce_seed,
        signer_index,
        SecNonceSpices::new()
            .with_seckey(*seckey)
            .with_message(&message),
    ).unwrap();
    first_round
}

pub fn musig2_receive_pub_nonce(ctx: KeyAggContext, peer_id: String, partial: musig2::PartialSignature) {

}



#[cfg(test)]
pub mod tests {
    use super::*;
    use secp256k1::PublicKey;
    #[test]
    fn test_musig2_agg_pubkeys() {
        let pubkeys = [
            "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
                .parse::<PublicKey>()
                .unwrap(),
            "02f3b071c064f115ca762ed88c3efd1927ea657c7949698b77255ea25751331f0b"
                .parse::<PublicKey>()
                .unwrap(),
            "03204ea8bc3425b2cbc9cb20617f67dc6b202467591d0b26d059e370b71ee392eb"
                .parse::<PublicKey>()
                .unwrap(),
        ];
        let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
        let aggregated_pubkey: secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
        assert_eq!(
            aggregated_pubkey,
            "02e272de44ea720667aba55341a1a761c0fc8fbe294aa31dbaf1cff80f1c2fd940"
                .parse()
                .unwrap()
        );
    }
}