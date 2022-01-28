use std::{collections::HashMap, convert::Infallible, sync::Arc};

use acdc::{Attestation, Authored, Hashed, PubKey, Signed};
use keri::prefix::Prefix;
use serde::Deserialize;
use tokio::sync::RwLock;
use warp::Filter;

use crate::{controller::Controller, WitnessConfig};

#[derive(Debug)]
pub enum ApiError {
    SigningError,
    InvalidAttestation,
    VerificationFailed,
    // InvalidIssuer,
    UnknownIssuer,
    SomeError(String),
}

impl warp::Reply for ApiError {
    fn into_response(self) -> warp::reply::Response {
        let mut resp = warp::reply::Response::new(format!("{:?}", self).into());
        *resp.status_mut() = warp::hyper::StatusCode::INTERNAL_SERVER_ERROR;
        resp
    }
}

impl warp::reject::Reject for ApiError {}

pub(crate) type AttestationDB = Arc<RwLock<HashMap<String, Signed<Hashed<Attestation>>>>>;

pub(crate) fn setup_routes(
    controller: Arc<RwLock<Controller>>,
    // dht_node: Arc<RwLock<Node>>,
    attest_db: AttestationDB,
) -> impl warp::Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
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
        .and(warp::any().map({
            let controller = controller.clone();
            move || controller.clone()
        }))
        .then(attest_create)
        .map(handle_result);

    let attest_receive_route = warp::path("attestations")
        .and(warp::post())
        .and(warp::body::bytes())
        .and(warp::any().map({
            let attest_db = attest_db;
            move || attest_db.clone()
        }))
        .and(warp::any().map({
            let controller = controller.clone();
            move || controller.clone()
        }))
        .then(attest_receive)
        .map(handle_result);

    let rotation_route = warp::path("rotate")
        .and(warp::post())
        .and(warp::body::bytes())
        .and(warp::any().map({
            let controller = controller;
            move || controller.clone()
        }))
        .then(rotate)
        .map(handle_result);

    attest_list_route
        .or(attest_create_route)
        .or(attest_receive_route)
        .or(rotation_route)
}

fn handle_result(result: Result<impl warp::Reply, impl warp::Reply>) -> impl warp::Reply {
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
    controller: Arc<RwLock<Controller>>,
) -> Result<warp::reply::Html<String>, ApiError> {
    // Hash
    let attest = Hashed::new(Attestation {
        issuer: controller.read().await.get_prefix().to_str(),
        ..attest
    });
    let attest_hash = attest.get_hash().to_string();
    log::info!("Created attestation {:?}", attest_hash);

    // Sign
    let sig = {
        let priv_key = &*controller.read().await;
        let msg = &Signed::get_json_bytes(&attest);
        priv_key
            .sign(msg)
            .map_err(|e| ApiError::SomeError(e.to_string()))?
    };
    let attest =
        Signed::new_with_keri_signatures(attest, &[sig]).map_err(|_| (ApiError::SigningError))?;

    // Save
    {
        let mut attest_db = attest_db.write().await;
        attest_db.insert(attest_hash.clone(), attest.clone());
    }

    Ok(warp::reply::html(attest.to_signed_json()))
}

async fn attest_receive(
    attest: warp::hyper::body::Bytes,
    attest_db: AttestationDB,
    controller: Arc<RwLock<Controller>>,
    // dht_node: Arc<RwLock<Node>>,
) -> Result<warp::reply::Json, ApiError> {
    // Parse
    let attest = std::str::from_utf8(&attest).map_err(|_| ApiError::InvalidAttestation)?;
    let attest = Signed::<Hashed<Attestation>>::from_signed_json(attest)
        .map_err(|_| ApiError::InvalidAttestation)?;
    let attest_issuer = attest.data.get_author_id();
    let attest_hash = attest.data.get_hash().to_string();
    log::info!(
        "Received attestation {:?} by {:?}",
        attest_hash,
        attest_issuer
    );

    // Verify
    {
        let key_config = controller
            .read()
            .await
            .get_public_keys(&attest_issuer.parse().unwrap_or_default())
            .await
            .map_err(|_e| ApiError::UnknownIssuer)?;

        let keys = {
            let mut keys = HashMap::new();
            keys.insert(attest_issuer.to_owned(), PubKey::KeriKeys(key_config));
            keys
        };
        attest
            .verify(&keys)
            .map_err(|_| ApiError::VerificationFailed)?;
    }

    // Save
    {
        let mut attest_db = attest_db.write().await;
        attest_db.insert(attest_hash, attest.clone());
    }

    Ok(warp::reply::json(&attest.data))
}

async fn rotate(
    rotation_data: warp::hyper::body::Bytes,
    controller: Arc<RwLock<Controller>>,
) -> Result<warp::reply::Html<String>, ApiError> {
    #[derive(Deserialize)]
    struct RotationData {
        witness_prefixes: Option<Vec<WitnessConfig>>,
        threshold: Option<u64>,
    }
    let rot_data: RotationData =
        serde_json::from_slice(&rotation_data).map_err(|e| ApiError::SomeError(e.to_string()))?;
    let witness_prefixes = match rot_data.witness_prefixes {
        Some(prefixes) => {
            if prefixes.is_empty() {
                None
            } else {
                Some(prefixes)
            }
        }
        None => None,
    };
    controller
        .write()
        .await
        .rotate(witness_prefixes, rot_data.threshold)
        .await
        .map_err(|e| ApiError::SomeError(e.to_string()))?;
    let current_kel = controller
        .read()
        .await
        .get_kel()
        .map_err(|e| ApiError::SomeError(e.to_string()))?;

    // TODO Should it return current kel?
    Ok(warp::reply::html(current_kel))
}
