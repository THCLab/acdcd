mod api;
mod controller;

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use controller::Controller;
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let Opts {
        kel_db_path,
        api_port,
    } = Opts::from_args();

    let cont = Controller::new(&kel_db_path, "".to_string(),  None, None);

    let controller = Arc::new(RwLock::new(cont));
    let attest_db: AttestationDB = Arc::new(RwLock::new(HashMap::new()));

    let routes = setup_routes(controller, attest_db);

    warp::serve(routes).run(([127, 0, 0, 1], api_port)).await;

    Ok(())
}
