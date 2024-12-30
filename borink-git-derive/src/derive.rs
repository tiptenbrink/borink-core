use std::{borrow::Cow, collections::HashMap, convert::Infallible};

use borink_error::StringContext;
use borink_git::{get_git_path, FinalResolved, GetOptions, GitAddress, GitError, StoreAddress};
#[cfg(feature = "kv")]
use borink_kv::KvError;
use camino::{Utf8Path, Utf8PathBuf};
use thiserror::Error as ThisError;
use tracing::debug;

#[cfg(feature = "typst-compile")]
use crate::derivers::CompileTypst;

#[derive(ThisError, Debug)]
pub enum DeriveError {
    #[error("error from plugin:\n{0}")]
    PluginError(StringContext),
    #[error("plugin {0} not found")]
    PluginNotFound(StringContext),
}

impl DeriveError {
    pub fn from_plugin<S: Into<String>>(err_message: S) -> Self {
        let str_ctx: String = err_message.into();

        Self::PluginError(str_ctx.into())
    }
}

#[derive(ThisError, Debug)]
#[non_exhaustive]
pub enum CacheErrorKind {
    #[cfg(feature = "kv")]
    #[error("error from kv cache:\n{0}")]
    KvCache(#[from] KvError),
    #[allow(dead_code)]
    #[error("error from other cache:\n{0}")]
    Other(StringContext),
}

#[derive(ThisError, Debug)]
pub enum GitDeriveError {
    #[error("error during git phase:\n{0}")]
    Git(#[from] GitError),
    #[error("address is absent:\n{0}")]
    Absent(StringContext),
    #[error("error during derive phase:\n{0}")]
    Derive(#[from] DeriveError),
    #[error("error during cache get/insert:\n{0}")]
    CacheError(#[from] CacheErrorKind),
}

pub struct ServerSettingsView<'a> {
    pub store_dir: &'a Utf8Path,
    pub verify_integrity: bool,
}

/// If `allow_exclusive` is true, it can clone the repo, fetch, and checkout the commit, otherwise
/// it will not perform any write operations. If the commit does not exist, it will return Absent.
fn git_resource_path(
    settings: &ServerSettingsView,
    mutate_store: bool,
    address: &GitAddress,
) -> Result<Utf8PathBuf, GitDeriveError> {
    debug!("Running git_resource_path...");
    let options = GetOptions::with_store_dir_mutate(settings.store_dir, mutate_store);

    match get_git_path(options, address) {
        Ok(FinalResolved::Path(path)) => Ok(path),
        Ok(FinalResolved::Absent) => Err(GitDeriveError::Absent("address is absent".into())),
        // Ok(FinalResolved::Empty) => todo!(),
        Err(e) => Err(e.into()),
    }
}

#[derive(Clone)]
pub struct DerivedResponse {
    pub headers: Vec<(String, String)>,
    pub bytes: Vec<u8>,
}

pub trait ResponseCache {
    type Error: Into<CacheErrorKind>;

    fn get<'a>(
        &'a self,
        derive_ctx: &str,
        address: &StoreAddress,
    ) -> Result<Option<Cow<'a, DerivedResponse>>, Self::Error>;

    fn insert(
        &mut self,
        derive_ctx: &str,
        address: &StoreAddress,
        response: DerivedResponse,
    ) -> Result<(), Self::Error>;

    fn cache_key(derive_ctx: &str, address: &StoreAddress) -> String {
        format!("borink-cache:{derive_ctx}:{}", address.as_str())
    }
}

impl From<Infallible> for CacheErrorKind {
    fn from(_: Infallible) -> Self {
        unreachable!("error should not occur!")
    }
}

impl ResponseCache for HashMap<String, DerivedResponse> {
    type Error = Infallible;

    fn get<'a>(
        &'a self,
        derive_ctx: &str,
        address: &StoreAddress,
    ) -> Result<Option<Cow<'a, DerivedResponse>>, Infallible> {
        Ok(self
            .get(&Self::cache_key(derive_ctx, address))
            .map(Cow::Borrowed))
    }

    fn insert(
        &mut self,
        derive_ctx: &str,
        address: &StoreAddress,
        response: DerivedResponse,
    ) -> Result<(), Infallible> {
        self.insert(Self::cache_key(derive_ctx, address), response);

        Ok(())
    }

    fn cache_key(derive_ctx: &str, address: &StoreAddress) -> String {
        std::format!("borink-cache:{derive_ctx}:{}", address.as_str())
    }
}

pub fn response_cache_map() -> HashMap<StoreAddress, DerivedResponse> {
    HashMap::new()
}

pub trait ResourceDeriver {
    fn derive(&self, path: &Utf8Path) -> Result<DerivedResponse, DeriveError>;
}

//pub type ResourceDeriver = Box<dyn Fn(&Utf8Path) -> Result<DerivedResponse, DeriveError>>;

pub fn derived_resource<C: ResponseCache>(
    settings: &ServerSettingsView,
    address: &GitAddress,
    derive_ctx: &str,
    use_cache: bool,
    mutate_store: bool,
    response_cache: &mut C,
    deriver: &dyn ResourceDeriver,
) -> Result<DerivedResponse, GitDeriveError> {
    let store_address: StoreAddress = address.into();

    if use_cache {
        if let Some(result) = response_cache
            .get(derive_ctx, &store_address)
            .map_err(|e| e.into())?
        {
            debug!(
                "Response cache hit for {}!",
                C::cache_key(derive_ctx, &store_address)
            );
            return Ok(result.into_owned());
        } else {
            debug!(
                "No response cache hit for {}",
                C::cache_key(derive_ctx, &store_address)
            );
        }
    } else if !use_cache {
        debug!("Cache disabled, not looking for hit.");
    }

    let path = git_resource_path(settings, mutate_store, address)?;

    let response = deriver.derive(&path)?;

    debug!("Function ran successfully, inserting into cache...");

    response_cache
        .insert(derive_ctx, &store_address, response.clone())
        .map_err(|e| e.into())?;

    Ok(response)
}

/// The PluginRegistry allows dynamic registration of ResourceDeriver functions that can take a file path and derive some bytes from it.
/// This means such functions can be registered at runtime and then referred to using their string name.
///
/// The underlying storage is just a boxed function pointer in a HashMap. By default it registers the "compile_typst_main" plugin.
pub struct PluginRegistry {
    storage: HashMap<String, Box<dyn ResourceDeriver>>,
}

#[cfg(feature = "typst-compile")]
pub const TYPST_PLUGIN_NAME: &str = "compile_typst_main";

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    pub fn new() -> Self {
        #[allow(unused_mut)]
        let mut registry = Self {
            storage: HashMap::new(),
        };

        #[cfg(feature = "typst-compile")]
        registry.register(TYPST_PLUGIN_NAME, CompileTypst);

        registry
    }

    /// Register a new function.
    pub fn register<S: Into<String>, D: ResourceDeriver + 'static>(&mut self, name: S, deriver: D) {
        self.storage.insert(name.into(), Box::new(deriver));
    }

    pub fn register_boxed<S: Into<String>>(&mut self, name: S, deriver: Box<dyn ResourceDeriver>) {
        self.storage.insert(name.into(), deriver);
    }

    /// Derive using the given plugin name. Errors if the plugin has not been registered. Requires
    /// a valid GitAddress. If combination of plugin name and address exists in the response cache,
    /// the cached value will be returned. For more details, also look at [`git_resource_path`].
    pub fn derive_with<C: ResponseCache>(
        &self,
        plugin_name: &str,
        settings: &ServerSettingsView,
        address: &GitAddress,
        use_cache: bool,
        mutate_store: bool,
        response_cache: &mut C,
    ) -> Result<DerivedResponse, GitDeriveError> {
        let function = if let Some(function) = self.storage.get(plugin_name) {
            function
        } else {
            return Err(DeriveError::PluginNotFound(plugin_name.into()).into());
        };

        derived_resource(
            settings,
            address,
            plugin_name,
            use_cache,
            mutate_store,
            response_cache,
            function.as_ref(),
        )
    }
}
