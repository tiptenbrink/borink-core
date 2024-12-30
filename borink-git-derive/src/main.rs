use borink_git_derive::cli::{server::run_cli, install_tracing};

use color_eyre::eyre::Report;

fn main() -> Result<(), Report> {
    install_tracing();
    color_eyre::install()?;

    run_cli()?;

    Ok(())
}
