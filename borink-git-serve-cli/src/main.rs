use borink_git_serve::cli::run_cli;
use color_eyre::Report;

fn main() -> Result<(), Report> {
    run_cli()?;

    Ok(())
}
