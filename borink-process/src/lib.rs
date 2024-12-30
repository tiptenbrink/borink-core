use borink_error::{ContextSource, StringContext};
use camino::Utf8PathBuf;
use duct::{cmd, IntoExecutablePath};
use std::ffi::OsStr;
use std::fmt::Debug;
use std::io::Error as IOError;
use std::process::ExitStatus;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum ProcessError {
    #[error("failed to decode process output:\n{0}")]
    Decode(StringContext),
    #[error("internal IO error when trying to run process:\n{0}")]
    IO(#[from] ContextSource<IOError>),
}

pub trait WrapIOProcessError<T> {
    fn to_process_err<S: Into<String>>(self, message: S) -> Result<T, ProcessError>;
}

impl<T> WrapIOProcessError<T> for Result<T, IOError> {
    fn to_process_err<S: Into<String>>(self, message: S) -> Result<T, ProcessError> {
        self.map_err(|e| ProcessError::IO(ContextSource::new(message, e)))
    }
}

pub struct EntrypointOutBytes {
    pub out: Vec<u8>,
    pub exit: ExitStatus,
}

pub struct EntrypointOut {
    pub out: String,
    pub exit: ExitStatus,
}

pub fn process_out<S: AsRef<str>>(bytes: Vec<u8>, info: S) -> Result<String, ProcessError> {
    Ok(String::from_utf8(bytes)
        .map_err(|e| {
            ProcessError::Decode(
                format!(
                    "info={} {}",
                    String::from_utf8_lossy(e.as_bytes()).into_owned(),
                    info.as_ref()
                )
                .into(),
            )
        })?
        .trim_end()
        .to_owned())
}

pub fn process_complete_bytes<P, E, S>(
    working_dir: P,
    program: E,
    args: Vec<S>,
) -> Result<EntrypointOutBytes, ProcessError>
where
    P: Into<Utf8PathBuf> + Debug + Clone,
    E: IntoExecutablePath + Debug + Clone,
    S: AsRef<OsStr> + Debug,
{
    let working_dir: Utf8PathBuf = working_dir.into();
    let working_dir_canon = working_dir.canonicalize_utf8().to_process_err(format!("Failed to canonicalize working dir {}", working_dir))?;

    let output = cmd(program.clone(), &args)
        .dir(&working_dir_canon)
        .stderr_to_stdout()
        .stdout_capture()
        .unchecked()
        .run()
        .to_process_err(format!(
            "process {:?} with args {:?} failed to run in {:?}",
            program, args, working_dir_canon
        ))?;

    Ok(EntrypointOutBytes {
        out: output.stdout,
        exit: output.status,
    })
}

pub fn process_complete_output<P, E, S>(
    working_dir: P,
    program: E,
    args: Vec<S>,
) -> Result<EntrypointOut, ProcessError>
where
    P: Into<Utf8PathBuf> + Debug + Clone,
    E: IntoExecutablePath + Debug + Clone,
    S: AsRef<OsStr> + Debug,
{
    let output = process_complete_bytes(working_dir, program, args)?;

    let out = process_out(output.out, "stdout")?;

    Ok(EntrypointOut {
        out,
        exit: output.exit,
    })
}
