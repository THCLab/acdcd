mod api;
mod controller;

use std::{collections::HashMap, net::IpAddr, path::PathBuf, sync::Arc};

use controller::Controller;
use figment::{
    providers::{Format, Json},
    Figment,
};
use keri::{event::sections::threshold::SignatureThreshold, prefix::BasicPrefix};
use serde::Deserialize;
use structopt::StructOpt;
use tokio::sync::RwLock;
use url::Url;

use self::api::{setup_routes, AttestationDB};

#[derive(Deserialize)]
struct Config {
    kel_db_path: PathBuf,
    api_host: String,
    /// Daemon API listen port.
    api_port: u16,
    witnesses: Option<Vec<BasicPrefix>>,
    known_resolvers: Option<Vec<String>>,
    witness_threshold: u64,
}

#[derive(Debug, StructOpt)]
struct Opts {
    #[structopt(short = "c", long, default_value = "config.json")]
    config_file: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let Opts { config_file } = Opts::from_args();

    let Config {
        kel_db_path,
        api_host,
        api_port,
        witnesses,
        witness_threshold,
        known_resolvers,
    } = Figment::new().join(Json::file(config_file)).extract()?;

    if witnesses.as_ref().is_some()
        && (witnesses.as_ref().unwrap().len() as u64) < witness_threshold
    {
        // not enough witnesses, any event can be accepted.
        Err(anyhow::anyhow!("Not enough witnesses provided"))
    } else {
        Ok(())
    }?;

    let resolvers = known_resolvers
        .unwrap_or_default()
        .iter()
        .map(|res| res.parse::<Url>().unwrap())
        .collect();
    let cont = Controller::new(
        &kel_db_path,
        resolvers,
        witnesses,
        Some(SignatureThreshold::Simple(witness_threshold)),
    );

    let controller = Arc::new(RwLock::new(cont));
    let attest_db: AttestationDB = Arc::new(RwLock::new(HashMap::new()));

    let routes = setup_routes(controller, attest_db);

    warp::serve(routes)
        .run((api_host.parse::<IpAddr>()?, api_port))
        .await;

    Ok(())
}
