mod api;

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use kademlia_dht::{Key, NodeData};
use openssl::pkey::{PKey, Private};
use rand::random;
use sha3::{Digest, Sha3_256};
use structopt::StructOpt;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
};

use self::api::{setup_routes, AttestationDB};

#[derive(Debug, StructOpt)]
struct Opts {
    /// Current user ID.
    #[structopt(short = "u", long)]
    user_id: String,

    /// Path to private key PEM file.
    /// If it doesn't exist it will be generated with a random key.
    #[structopt(short = "k", long, default_value = "acdcd.key")]
    priv_key_path: PathBuf,

    /// Daemon API listen port.
    #[structopt(long, default_value = "13434")]
    api_port: u16,

    /// DHT listen port.
    #[structopt(long, default_value = "13435")]
    dht_port: u16,

    /// DHT bootstrap IP address.
    #[structopt(long)]
    bootstrap_addr: Option<SocketAddr>,
}

pub(crate) fn get_dht_key(value: &[u8]) -> Key {
    let mut hasher = Sha3_256::default();
    hasher.update(value);
    Key(hasher.finalize()[..].try_into().unwrap())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let Opts {
        user_id,
        priv_key_path,
        api_port,
        dht_port,
        bootstrap_addr,
    } = Opts::from_args();

    let priv_key = load_priv_key(&priv_key_path).await?;

    let mut dht_node = kademlia_dht::Node::new(
        "0.0.0.0",
        &dht_port.to_string(),
        bootstrap_addr.map(|addr| NodeData {
            id: Key(random()),
            addr: addr.to_string(),
        }),
    );

    if let Ok(key) = priv_key.raw_public_key() {
        dht_node.insert(get_dht_key(user_id.as_bytes()), &base64::encode(key));
    }

    let dht_node = Arc::new(RwLock::new(dht_node));
    let priv_key = Arc::new(RwLock::new(priv_key));
    let attest_db: AttestationDB = Arc::new(RwLock::new(HashMap::new()));

    let routes = setup_routes(priv_key, dht_node, attest_db);

    warp::serve(routes).run(([127, 0, 0, 1], api_port)).await;

    Ok(())
}

async fn load_priv_key(path: &Path) -> anyhow::Result<PKey<Private>> {
    let key = if path.exists() {
        log::debug!("Loading priv key from {:?}", path);
        let mut key_file = File::open(path)
            .await
            .with_context(|| format!("Can't open priv key file {:?}", path))?;
        let mut key_pem = Vec::new();
        key_file
            .read_to_end(&mut key_pem)
            .await
            .context("Can't read priv key file")?;
        PKey::private_key_from_pem(&key_pem).context("Can't parse priv key file")?
    } else {
        log::debug!("Generating priv key to {:?}", path);
        let key = PKey::generate_ed25519().context("Can't generate priv key")?;
        let key_pem = key
            .private_key_to_pem_pkcs8()
            .context("Can't encode priv key")?;
        let mut key_file = File::create(&path)
            .await
            .with_context(|| format!("Can't create priv key file {:?}", path))?;
        key_file
            .write_all(&key_pem)
            .await
            .context("Can't write to priv key file")?;
        key
    };

    if let Ok(key) = key.raw_public_key() {
        log::info!("Current user pub key: {:?}", base64::encode(key));
    }

    Ok(key)
}
