use std::{collections::HashMap, convert::Infallible, sync::Arc};

use acdc::{Attestation, Hashed, Signed};
use openssl::{
    pkey::{PKey, Private},
    sign::Signer,
};
use tokio::sync::RwLock;
use warp::Filter;

#[derive(Debug)]
enum ApiError {
    SigningError,
    InvalidAttestation,
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

pub(crate) type KeyDB = Arc<RwLock<HashMap<String, acdc::PubKey>>>;

pub(crate) fn setup_routes(
    attest_db: AttestationDB,
    pub_keys: KeyDB,
    priv_key: Arc<RwLock<PKey<Private>>>,
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
            let priv_key = priv_key;
            move || priv_key.clone()
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
            let pub_keys = pub_keys;
            move || pub_keys.clone()
        }))
        .then(attest_receive)
        .map(handle_result);

    attest_list_route
        .or(attest_create_route)
        .or(attest_receive_route)
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
    priv_key: Arc<RwLock<PKey<Private>>>,
) -> Result<warp::reply::Html<String>, ApiError> {
    let attest = Hashed::new(attest);
    let sig = {
        let priv_key = &*priv_key.read().await;
        let mut signer =
            Signer::new_without_digest(priv_key).map_err(|_| (ApiError::SigningError))?;
        signer
            .sign_oneshot_to_vec(&Signed::get_json_bytes(&attest))
            .map_err(|_| (ApiError::SigningError))?
    };
    let attest = Signed::new_with_ed25519(attest, &sig).map_err(|_| (ApiError::SigningError))?;
    {
        let mut attest_db = attest_db.write().await;
        attest_db.insert(attest.data.get_hash().to_string(), attest.clone());
    }
    Ok(warp::reply::html(attest.to_signed_json()))
}

async fn attest_receive(
    attest: warp::hyper::body::Bytes,
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
