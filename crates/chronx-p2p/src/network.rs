use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    gossipsub, identify, kad, noise, ping, tcp, yamux,
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use libp2p_swarm::NetworkBehaviour;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::P2pConfig;
use crate::message::P2pMessage;

/// Combined libp2p network behaviour for ChronX.
///
/// The `#[derive(NetworkBehaviour)]` macro auto-generates a
/// `ChronxBehaviourEvent` enum with one variant per field.
#[derive(NetworkBehaviour)]
pub struct ChronxBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}

/// Application-facing handle returned from `P2pNetwork::new()`.
pub struct P2pHandle {
    /// Send here to broadcast a message to all gossip peers.
    pub outbound_tx: mpsc::Sender<P2pMessage>,
    /// Receive here to consume messages arriving from peers.
    pub inbound_rx: mpsc::Receiver<P2pMessage>,
    /// Local libp2p peer identity.
    pub local_peer_id: PeerId,
}

/// Owns the libp2p Swarm. Pass to `tokio::spawn(network.run())`.
pub struct P2pNetwork {
    swarm: Swarm<ChronxBehaviour>,
    topic: gossipsub::IdentTopic,
    outbound_rx: mpsc::Receiver<P2pMessage>,
    inbound_tx: mpsc::Sender<P2pMessage>,
}

impl P2pNetwork {
    /// Build the network and return `(P2pNetwork, P2pHandle)`.
    pub fn new(
        config: &P2pConfig,
    ) -> Result<(Self, P2pHandle), Box<dyn std::error::Error + Send + Sync>> {
        let topic = gossipsub::IdentTopic::new(&config.vertex_topic);

        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key: &libp2p::identity::Keypair| {
                let message_id_fn = |msg: &gossipsub::Message| {
                    let mut s = DefaultHasher::new();
                    msg.data.hash(&mut s);
                    gossipsub::MessageId::from(s.finish().to_string())
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .build()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                let store = kad::store::MemoryStore::new(key.public().to_peer_id());
                let kademlia = kad::Behaviour::new(key.public().to_peer_id(), store);

                let identify = identify::Behaviour::new(identify::Config::new(
                    config.protocol_version.clone(),
                    key.public(),
                ));

                let ping = ping::Behaviour::default();

                Ok(ChronxBehaviour { gossipsub, kademlia, identify, ping })
            })?
            .build();

        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

        let listen_addr: Multiaddr = config.listen_addr.parse()?;
        swarm.listen_on(listen_addr)?;

        for addr_str in &config.bootstrap_peers {
            if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = addr.iter().last() {
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                    debug!(peer = %peer_id, "added bootstrap peer");
                }
            }
        }

        let local_peer_id = *swarm.local_peer_id();
        let (outbound_tx, outbound_rx) = mpsc::channel(256);
        let (inbound_tx, inbound_rx) = mpsc::channel(256);

        let network = P2pNetwork { swarm, topic, outbound_rx, inbound_tx };
        let handle = P2pHandle { outbound_tx, inbound_rx, local_peer_id };

        Ok((network, handle))
    }

    /// Drive the P2P event loop. Run in a dedicated tokio task.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.outbound_rx.recv() => {
                    let data = msg.to_bytes();
                    if let Err(e) = self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(self.topic.clone(), data)
                    {
                        warn!(error = %e, "gossipsub publish failed");
                    }
                }

                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!(addr = %address, "P2P listening on");
                        }
                        SwarmEvent::Behaviour(ChronxBehaviourEvent::Gossipsub(
                            gossipsub::Event::Message { message, .. },
                        )) => {
                            match P2pMessage::from_bytes(&message.data) {
                                Ok(msg) => { let _ = self.inbound_tx.send(msg).await; }
                                Err(e) => debug!(error = %e, "failed to decode gossip message"),
                            }
                        }
                        SwarmEvent::Behaviour(ChronxBehaviourEvent::Identify(
                            identify::Event::Received { peer_id, info, .. },
                        )) => {
                            for addr in info.listen_addrs {
                                self.swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .add_address(&peer_id, addr);
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            debug!(peer = %peer_id, "connection established");
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            debug!(peer = %peer_id, "connection closed");
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
