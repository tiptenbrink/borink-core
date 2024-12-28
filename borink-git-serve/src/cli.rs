use clap::Parser;
use color_eyre::eyre::{bail, Report};

use crate::{derive::TYPST_PLUGIN_NAME, server::{default_server, RequestInitSettings, ServerConfig}, ServerSettingsView};

#[derive(Parser, Debug)]
#[command()]
pub struct Args {
    /// Repository url
    #[arg(short, long, env)]
    repo_url: String,

    #[arg(short, long, env)]
    exposed: bool,

    #[arg(short, long, env, default_value_t = 8004)]
    port: u16,

    #[arg(short, long, env)]
    subpath: Option<String>,

    #[arg(short, long, env, default_value = "./store")]
    git_store_dir: String,

    #[arg(short, long, env, default_value = "")]
    git_subpath: String,

    #[arg(short, long, env, default_value_t = false)]
    trusted: bool,

    #[arg(short, long, env)]
    trust_key: Option<String>,

    #[arg(short, long, env, default_value = "./db.sqlite")]
    db_path: String
}

pub fn run_cli() -> Result<(), Report> {
    let parsed = Args::parse();

    let hostname = if parsed.exposed {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };

    let server_config = ServerConfig {
        hostname,
        port: parsed.port
    };

    let server_settings = ServerSettingsView {
        store_dir: parsed.git_store_dir.as_str().into(),
        verify_integrity: false,
    };

    let init_settings = RequestInitSettings {
        repo_url: &parsed.repo_url,
        git_subpath: &parsed.git_subpath,
        plugin_name: TYPST_PLUGIN_NAME,
        default_path: "main",
        subpath: parsed.subpath.as_deref(),
        trust_key: parsed.trust_key.as_deref(),
    };

    if !parsed.trusted && parsed.trust_key.is_none() {
        bail!("If no trust key is provided, TRUSTED must be explicitly set!")
    }

    default_server(server_config, &server_settings, init_settings, parsed.db_path.as_str().into())
}