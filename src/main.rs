mod api;
mod controller;

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use controller::Controller;
use keri::{event::sections::threshold::SignatureThreshold, prefix::BasicPrefix};
use structopt::StructOpt;
use tokio::sync::RwLock;

use self::api::{setup_routes, AttestationDB};

#[derive(Debug, StructOpt)]
struct Opts {
    #[structopt(short = "d", long, default_value = "controller_db")]
    kel_db_path: PathBuf,

    /// Daemon API listen port.
    #[structopt(long, default_value = "13434")]
    api_port: u16,

    #[structopt(short = "r", default_value = "http://127.0.0.1:9599")]
    resolver_address: String,

    #[structopt(short = "w")]
    witnesses: Option<Vec<String>>,

    #[structopt(short = "t", default_value = "0")]
    witness_threshold: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let Opts {
        kel_db_path,
        api_port,
        resolver_address,
        witnesses,
        witness_threshold,
    } = Opts::from_args();

    if witnesses.as_ref().is_some()
        && (witnesses.as_ref().unwrap().len() as u64) < witness_threshold
    {
        // not enough witnesses, any event can be accepted.
        Err(anyhow::anyhow!("Not enough witnesses provided"))
    } else {
        Ok(())
    }?;

    let wits: Option<Vec<BasicPrefix>> =
        witnesses.map(|wit_list| wit_list.iter().map(|w| w.parse().unwrap()).collect());

    let cont = Controller::new(
        &kel_db_path,
        resolver_address,
        wits,
        Some(SignatureThreshold::Simple(witness_threshold)),
    );

    let controller = Arc::new(RwLock::new(cont));
    let attest_db: AttestationDB = Arc::new(RwLock::new(HashMap::new()));

    let routes = setup_routes(controller, attest_db);

    warp::serve(routes).run(([127, 0, 0, 1], api_port)).await;

    Ok(())
}
