mod api;
mod controller;

use std::{collections::HashMap, net::IpAddr, path::PathBuf, sync::Arc};

use anyhow::Result;
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
    bootstrap: BootstrapConfig,
}

#[derive(Deserialize)]
struct BootstrapConfig {
    witnesses: Option<Vec<WitnessConfig>>,
    known_resolvers: Option<Vec<Url>>,
    witness_threshold: u64,
}

#[derive(Deserialize)]
pub struct WitnessConfig {
    pub aid: Option<BasicPrefix>,
    pub location: Option<Url>,
}

impl WitnessConfig {
    pub fn get_aid(&self) -> Result<BasicPrefix> {
        match &self.aid {
            Some(aid) => Ok(aid.clone()),
            None => {
                //ask about prefix
                todo!()
            }
        }
    }

    pub fn get_location(&self) -> Result<Url> {
        self.location
            .as_ref()
            .cloned()
            .ok_or(anyhow::anyhow!("No location set"))
    }
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
        bootstrap,
    } = Figment::new().join(Json::file(config_file)).extract()?;

    match bootstrap.witnesses {
        Some(ref wit) if (wit.len() as u64) < bootstrap.witness_threshold => {
            // not enough witnesses, any event can be accepted.
            Err(anyhow::anyhow!("Not enough witnesses provided"))
        }
        _ => Ok(()),
    }?;

    let cont = Controller::new(
        &kel_db_path,
        bootstrap.known_resolvers.unwrap_or_default(),
        bootstrap.witnesses,
        Some(SignatureThreshold::Simple(bootstrap.witness_threshold)),
    )?;

    let controller = Arc::new(RwLock::new(cont));
    let attest_db: AttestationDB = Arc::new(RwLock::new(HashMap::new()));

    let routes = setup_routes(controller, attest_db);

    warp::serve(routes)
        .run((api_host.parse::<IpAddr>()?, api_port))
        .await;

    Ok(())
}
