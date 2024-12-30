use borink_git_derive::cli::{client::run_cli, install_tracing};
use color_eyre::Report;

fn main() -> Result<(), Report> {
    install_tracing();
    color_eyre::install()?;
    
    run_cli()?;

    Ok(())
}