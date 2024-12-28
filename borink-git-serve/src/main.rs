#[cfg(feature = "cli")]
use borink_git_serve::cli::run_cli;

fn main() {
    #[cfg(feature = "cli")]
    run_cli().unwrap();

    #[cfg(not(feature = "cli"))]
    cli_not_available()    
}

#[cfg(not(feature = "cli"))]
fn cli_not_available() {
    panic!("Enable 'cli' feature to run!")
}