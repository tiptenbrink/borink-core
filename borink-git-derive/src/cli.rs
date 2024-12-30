use tracing_error::ErrorLayer;
use tracing_subscriber::{prelude::*, EnvFilter};
use color_eyre::Report;
use clap::Parser;

pub fn install_tracing() {
    // We have to add the error layer (see the examples in color-eyre), so we can't just use the default init
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(false);

    let filter_layer = EnvFilter::from_default_env();

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(filter_layer)
        .with(ErrorLayer::default())
        .init();
}

#[cfg(feature = "server-cli")]
pub mod server {
    use super::*;
    use color_eyre::eyre::bail;

    #[cfg(feature = "typst-compile")]
    use crate::derive::TYPST_PLUGIN_NAME;

    #[cfg(feature = "typst-compile")]
    const DEFAULT_PLUGIN: &str = TYPST_PLUGIN_NAME;

    #[cfg(not(feature = "typst-compile"))]
    const DEFAULT_PLUGIN: &str = "borink-git-derive-no-default-plugin";

    use crate::{server::{default_server, RequestInitSettings, ServerConfig}, ServerSettingsView};

    #[derive(Parser, Debug)]
    #[command()]
    struct Args {
        /// Repository url
        #[arg(short, long, env)]
        repo_url: String,

        #[arg(long, env)]
        exposed: bool,

        #[arg(long, env, default_value = DEFAULT_PLUGIN)]
        plugin_name: String,

        #[arg(long, env, default_value = "main")]
        default_pattern: String,

        #[arg(short, long, env, default_value_t = 8004)]
        port: u16,

        #[arg(long, env)]
        subpath: Option<String>,

        #[arg(long, env, default_value = "./store")]
        git_store_dir: String,

        #[arg(long, env, default_value = "")]
        git_subpath: String,

        #[arg(long, env, default_value_t = false)]
        trusted: bool,

        #[arg(long, env)]
        trust_key: Option<String>,

        #[arg(long, env, default_value = "./db.sqlite")]
        db_path: String,
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
            port: parsed.port,
        };

        let server_settings = ServerSettingsView {
            store_dir: parsed.git_store_dir.as_str().into(),
            verify_integrity: false,
        };

        #[cfg(feature = "typst-compile")]

        let init_settings = RequestInitSettings {
            repo_url: &parsed.repo_url,
            git_subpath: &parsed.git_subpath,
            plugin_name: &parsed.plugin_name,
            default_path: &parsed.default_pattern,
            subpath: parsed.subpath.as_deref(),
            trust_key: parsed.trust_key.as_deref(),
        };

        if !parsed.trusted && parsed.trust_key.is_none() {
            bail!("If no trust key is provided, TRUSTED must be explicitly set!")
        }

        default_server(
            server_config,
            &server_settings,
            init_settings,
            parsed.db_path.as_str().into(),
        )
    }
}

#[cfg(feature = "client-cli")]
pub mod client {
    use super::*;
    use crate::client::sync_git_refs;

    #[derive(Parser, Debug)]
    #[command()]
    struct Args {
        // Git repository URL to fetch tags from using ls-remote
        #[arg(short, long, env)]
        repo_url: String,

        // Server URL to sync the tags to
        #[arg(short, long, env)]
        sync_url: String,

        // If server requires trust key, use this key to authenticate
        #[arg(short, long, env)]
        trust_key: Option<String>,
    }

    pub fn run_cli() -> Result<(), Report> {
        let args = Args::parse();

        sync_git_refs(&args.repo_url, &args.sync_url, args.trust_key.as_deref())?;

        Ok(())
    }
}