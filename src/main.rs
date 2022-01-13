mod api;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use openssl::pkey::{PKey, Private};
use structopt::StructOpt;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
};

use self::api::{setup_routes, AttestationDB};

#[derive(Debug, StructOpt)]
struct Opts {
    /// Path to private key PEM file.
    /// If it doesn't exist it will be generated with a random key.
    #[structopt(short = "k", long = "priv-key", default_value = "acdcd.key")]
    priv_key_path: PathBuf,

    /// Path to public keys JSON file.
    /// The file should contain a map of user IDs and their base64-encoded ED25519 public keys
    #[structopt(short = "K", long = "pub-keys", default_value = "pub_keys.json")]
    pub_keys_path: PathBuf,

    /// Daemon API port.
    #[structopt(short, long, default_value = "13434")]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Opts {
        priv_key_path,
        pub_keys_path,
        port,
    } = Opts::from_args();

    let priv_key = Arc::new(RwLock::new(load_priv_key(&priv_key_path).await?));
    let pub_keys = Arc::new(RwLock::new(load_pub_keys(&pub_keys_path).await?));
    let attest_db: AttestationDB = Arc::new(RwLock::new(HashMap::new()));

    let routes = setup_routes(attest_db, pub_keys, priv_key);

    warp::serve(routes).run(([127, 0, 0, 1], port)).await;

    Ok(())
}

async fn load_priv_key(path: &Path) -> anyhow::Result<PKey<Private>> {
    let key = if path.exists() {
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
        println!("Pub key: {}", base64::encode(key));
    }

    Ok(key)
}

async fn load_pub_keys(path: &Path) -> anyhow::Result<HashMap<String, acdc::PubKey>> {
    let mut keys_file = File::open(path)
        .await
        .with_context(|| format!("Can't open pub keys file {:?}", path))?;
    let mut json = String::new();
    keys_file
        .read_to_string(&mut json)
        .await
        .context("Can't read pub keys file")?;
    let keys: HashMap<String, String> =
        serde_json::from_str(&json).context("Can't parse pub keys file")?;
    let keys = keys
        .into_iter()
        .map(|(id, key)| {
            let key = acdc::PubKey::ED25519(
                base64::decode(key).with_context(|| format!("Invalid base64 for {:?}", id))?,
            );
            Ok((id, key))
        })
        .collect::<Result<_, anyhow::Error>>()
        .context("Can't parse pub keys")?;
    Ok(keys)
}
