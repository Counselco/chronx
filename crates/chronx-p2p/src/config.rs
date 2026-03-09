use std::path::PathBuf;

/// Configuration for the ChronX P2P network.
#[derive(Debug, Clone)]
pub struct P2pConfig {
    /// Local listen address (e.g. "/ip4/0.0.0.0/tcp/7777").
    pub listen_addr: String,
    /// Bootstrap peer multiaddresses.
    pub bootstrap_peers: Vec<String>,
    /// Protocol version string advertised to peers.
    pub protocol_version: String,
    /// GossipSub topic name for broadcasting new vertices.
    pub vertex_topic: String,
    /// Optional path to a persistent identity key file.
    /// If set and the file exists, the keypair is loaded from it.
    /// If set and the file does not exist, a new keypair is generated and saved.
    /// If None, a fresh random identity is used each run.
    pub identity_file: Option<PathBuf>,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/7777".into(),
            bootstrap_peers: Vec::new(),
            protocol_version: "/chronx/1.0.0".into(),
            vertex_topic: "chronx-vertices".into(),
            identity_file: None,
        }
    }
}
