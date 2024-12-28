use borink_git_serve::cli::{run_cli, install_tracing};
use color_eyre::Report;

fn main() -> Result<(), Report> {
    install_tracing();
    color_eyre::install()?;
    run_cli()?;

    Ok(())
}
