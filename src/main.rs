use std::{
    collections::HashMap,
    convert::Infallible,
    path::{Path, PathBuf},
    sync::Arc,
};

use acdc::{Attestation, Hashed, Signed};
use anyhow::Context;
use openssl::{
    pkey::{PKey, Private},
    sign::Signer,
};
use structopt::StructOpt;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
};
use warp::{
    hyper::{body::Bytes, StatusCode},
    reply::Response,
    Filter, Reply,
};

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

#[derive(Debug)]
enum ApiError {
    SigningError,
    InvalidAttestation,
}

impl Reply for ApiError {
    fn into_response(self) -> Response {
        let mut resp = Response::new(format!("{:?}", self).into());
        *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        resp
    }
}

impl warp::reject::Reject for ApiError {}

type AttestationDB = Arc<RwLock<HashMap<String, Signed<Hashed<Attestation>>>>>;

type KeyDB = Arc<RwLock<HashMap<String, acdc::PubKey>>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Opts {
        priv_key_path,
        pub_keys_path,
        port,
    } = Opts::from_args();

    let priv_key = load_priv_key(&priv_key_path).await?;
    let pub_keys = Arc::new(RwLock::new(load_pub_keys(&pub_keys_path).await?));
    let attest_db: AttestationDB = Arc::new(RwLock::new(HashMap::new()));

    let attest_list_route = warp::path("attestations")
        .and(warp::get())
        .and(warp::any().map({
            let attest_db = attest_db.clone();
            move || attest_db.clone()
        }))
        .then(attest_list)
        .map(handle_result);

    let attest_create_route = warp::path("attestations")
        .and(warp::path("create"))
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map({
            let attest_db = attest_db.clone();
            move || attest_db.clone()
        }))
        .and(warp::any().map(move || priv_key.clone()))
        .then(attest_create)
        .map(handle_result);

    let attest_receive_route = warp::path("attestations")
        .and(warp::post())
        .and(warp::body::bytes())
        .and(warp::any().map({
            let attest_db = attest_db.clone();
            move || attest_db.clone()
        }))
        .and(warp::any().map({
            let pub_keys = pub_keys.clone();
            move || pub_keys.clone()
        }))
        .then(attest_receive)
        .map(handle_result);

    let routes = attest_list_route
        .or(attest_create_route)
        .or(attest_receive_route);

    warp::serve(routes).run(([127, 0, 0, 1], port)).await;

    Ok(())
}

fn handle_result(result: Result<impl Reply, impl Reply>) -> impl Reply {
    match result {
        Ok(val) => val.into_response(),
        Err(err) => err.into_response(),
    }
}

async fn attest_list(attest_db: AttestationDB) -> Result<warp::reply::Json, Infallible> {
    let attest_db = attest_db.read().await;
    let attests = attest_db
        .iter()
        .map(|(_id, attest)| &attest.data)
        .collect::<Vec<_>>();
    Ok(warp::reply::json(&attests))
}

async fn attest_create(
    attest: Attestation,
    attest_db: AttestationDB,
    key: PKey<Private>,
) -> Result<warp::reply::Json, ApiError> {
    let attest = Hashed::new(attest);
    let mut signer = Signer::new_without_digest(&key).map_err(|_| (ApiError::SigningError))?;
    let sig = signer
        .sign_oneshot_to_vec(&Signed::get_json_bytes(&attest))
        .map_err(|_| (ApiError::SigningError))?;
    let attest = Signed::new_with_ed25519(attest, &sig).map_err(|_| (ApiError::SigningError))?;
    {
        let mut attest_db = attest_db.write().await;
        attest_db.insert(attest.data.get_hash().to_string(), attest.clone());
    }
    Ok(warp::reply::json(&attest.data))
}

async fn attest_receive(
    attest: Bytes,
    attest_db: AttestationDB,
    pub_keys: KeyDB,
) -> Result<warp::reply::Json, ApiError> {
    let attest = std::str::from_utf8(&attest).map_err(|_| ApiError::InvalidAttestation)?;
    let attest = Signed::<Hashed<Attestation>>::from_signed_json(attest)
        .map_err(|_| ApiError::InvalidAttestation)?;
    {
        let pub_keys = pub_keys.read().await;
        attest
            .verify(&pub_keys)
            .map_err(|_| ApiError::InvalidAttestation)?;
    }
    {
        let mut attest_db = attest_db.write().await;
        attest_db.insert(attest.data.get_hash().to_string(), attest.clone());
    }
    Ok(warp::reply::json(&attest.data))
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
