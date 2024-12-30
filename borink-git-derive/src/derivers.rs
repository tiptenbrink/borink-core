use borink_process::{process_complete_bytes, process_out, EntrypointOutBytes};
use camino::Utf8Path;
use tracing::debug;

use crate::derive::{DeriveError, DerivedResponse, ResourceDeriver};

#[cfg(feature = "typst-compile")]
pub fn compile_typst_document(
    target_path: &Utf8Path,
    input_path: &str,
) -> Result<Vec<u8>, DeriveError> {
    debug!("Compiling typst document with input path {}...", input_path);
    let main_file = target_path.join(input_path);
    let out_file = "-";
    match process_complete_bytes(
        ".",
        "typst",
        vec!["compile", main_file.as_str(), out_file],
    ) {
        Ok(EntrypointOutBytes { out, exit }) => {
            if exit.success() {
                Ok(out)
            } else {
                let additional_err = match process_out(out, "err") {
                    Ok(err) => err,
                    Err(_) => "could not decode stderr as utf-8 string".to_owned(),
                };

                Err(DeriveError::from_plugin(format!(
                    "Failed to compile Typst! {}",
                    additional_err
                )))
            }
        }
        Err(e) => Err(DeriveError::from_plugin(format!(
            "Failed to compile Typst! {}",
            e
        ))),
    }
}

#[cfg(feature = "typst-compile")]
fn compile_typst_main(path: &Utf8Path) -> Result<DerivedResponse, DeriveError> {
    let out = compile_typst_document(path, "main.typ")?;
    let response = DerivedResponse {
        headers: vec![("Content-Type".to_owned(), "application/pdf".to_owned())],
        bytes: out,
    };
    Ok(response)
}

#[cfg(feature = "typst-compile")]
pub struct CompileTypst;

#[cfg(feature = "typst-compile")]
impl ResourceDeriver for CompileTypst {
    fn derive(&self, path: &Utf8Path) -> Result<DerivedResponse, DeriveError> {
        compile_typst_main(path)
    }
}
