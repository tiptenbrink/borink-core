
use std::borrow::{Borrow, Cow};
use std::io::{Cursor, Empty, Read};
use camino::Utf8Path;
use tracing::{debug, error, info};
use crate::derive::{DerivedResponse, PluginRegistry, ResponseCache, ServerSettingsView};
use crate::derive::{CacheErrorKind, GitDeriveError};
use borink_git::{is_hexadecimal, CommitHash, CommitHashBuf, GitAddress, GitRefGuardedStore, GitRefStore, GitRelativePath};
use borink_kv::{
    join_prefix_with_meta, Database, read_meta, DatabaseRef, KvError, KvMetaValue, KvMetadata,
};
use color_eyre::Report;
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Request, Response, Server};
use borink_git::ReadGuard;

fn redirect(location: &str) -> Response<Cursor<Vec<u8>>> {
    Response::from_data([]).with_status_code(303).with_header(Header::from_bytes("Location", location).unwrap())
}

const KEY_HEADER_NAME: &str = "typst-serve-key";
const PATTERN_VALUE_HEADER_NAME: &str = "typst-serve-pattern-value";
const RELOAD_HEADER_NAME: &str = "typst-serve-reload";

fn create_response(state: HandleState) -> Response<Cursor<Vec<u8>>> {
    assert!(state.resolved());
    debug!("Handle state resolved, returning response...");
    match state {
        HandleState::NotFound => Response::from_data([]).with_status_code(404),
        HandleState::Redirect(location) => redirect(location.as_ref()),
        HandleState::BadRequest(message) => Response::from_string(message).with_status_code(400),
        HandleState::Response(derived_response) => {
            let mut response = Response::from_data(derived_response.bytes);
            for (k, v) in derived_response.headers {
                response.add_header(Header::from_bytes(k, v).unwrap());
            }
            response
        }
        HandleState::Pattern(_) => unreachable!("Only resolved should reach this point."),
    }
}

fn send_response(state: HandleState, request: Request) {
    assert!(state.resolved());
    debug!("Handle state resolved, returning response...");
    match state {
        HandleState::NotFound => request.respond(Response::empty(404)).unwrap(),
        HandleState::Redirect(location) => request.respond(redirect(location.as_ref())).unwrap(),
        HandleState::BadRequest(message) => request
            .respond(Response::from_string(message).with_status_code(400))
            .unwrap(),
        HandleState::Response(derived_response) => {
            let mut response = Response::from_data(derived_response.bytes);
            for (k, v) in derived_response.headers {
                response.add_header(Header::from_bytes(k, v).unwrap());
            }
            request.respond(response).unwrap()
        }
        HandleState::Pattern(_) => unreachable!("Only resolved should reach this point."),
    }
}


#[derive(Debug)]
enum EarlyResolve<'a> {
    NotFound,
    BadRequest(String),
    Redirect(Cow<'a, str>),
}

impl<'a> EarlyResolve<'a> {
    fn redirect<S: Into<Cow<'a, str>>>(location: S) -> Self {
        Self::Redirect(location.into())
    }

    fn into_response(&self) -> Response<Cursor<Vec<u8>>> {
        debug!("Early resolve {:?}, returning response...", &self);
        match &self {
            EarlyResolve::NotFound => Response::from_data([]).with_status_code(404),
            EarlyResolve::Redirect(location) => redirect(location.as_ref()),
            EarlyResolve::BadRequest(message) => Response::from_string(message).with_status_code(400),
        }
    }
}

fn parse_url<'a>(
    url: &'a str,
    default_pattern: &str,
    sub_path: Option<&str>,
) -> Result<&'a str, EarlyResolve<'a>> {
    let url_parts = url.split("/").collect::<Vec<&str>>();

    let pattern_path = if let Some(sub_path) = sub_path {
        // We expect a valid path to look something like ["", "<sub_path>", "<pattern>"]
        if url_parts.len() < 2 || url_parts[1] != sub_path {
            return Err(EarlyResolve::NotFound)
        }

        // We have at least ["?", "<sub_path>"] now

        if url_parts.len() == 2 || url_parts[3].is_empty() {
            let location = format!("/{}/{}", sub_path, default_pattern);
            return Err(EarlyResolve::redirect(location))
        }

        if url_parts.len() > 3 {
            let location = format!("/{}/{}", sub_path, url_parts[2]);
            return Err(EarlyResolve::redirect(location))
        }

        url_parts[2]
    } else {
        // We expect a valid path to look something like ["", "<pattern>"]

        if url_parts.len() < 2 || url_parts[1].is_empty() {
            let location = format!("/{}", default_pattern);
            return Err(EarlyResolve::redirect(location))
        }

        // We have at least ["?", "<non_empty>"] now

        if url_parts.len() > 2 {
            let location = format!("/{}", url_parts[1]);
            return Err(EarlyResolve::redirect(location))
        }

        url_parts[1]
    };

    Ok(pattern_path)
}

fn pattern_from_url<'a>(
    url: &'a str,
    default_pattern: &str,
    sub_path: Option<&str>,
) -> HandleState<'a> {
    let url_parts = url.split("/").collect::<Vec<&str>>();

    let pattern_path = if let Some(sub_path) = sub_path {
        // We expect a valid path to look something like ["", "<sub_path>", "<pattern>"]
        if url_parts.len() < 2 || url_parts[1] != sub_path {
            return HandleState::NotFound;
        }

        // We have at least ["?", "<sub_path>"] now

        if url_parts.len() == 2 || url_parts[3].is_empty() {
            let location = format!("/{}/{}", sub_path, default_pattern);
            return HandleState::redirect(location);
        }

        if url_parts.len() > 3 {
            let location = format!("/{}/{}", sub_path, url_parts[2]);
            return HandleState::redirect(location);
        }

        url_parts[2]
    } else {
        // We expect a valid path to look something like ["", "<pattern>"]

        if url_parts.len() < 2 || url_parts[1].is_empty() {
            let location = format!("/{}", default_pattern);
            return HandleState::redirect(location);
        }

        // We have at least ["?", "<non_empty>"] now

        if url_parts.len() > 2 {
            let location = format!("/{}", url_parts[1]);
            return HandleState::redirect(location);
        }

        url_parts[1]
    };

    HandleState::Pattern(pattern_path)
}

fn read_headers(headers: &[tiny_http::Header]) -> Vec<(&str, &str)> {
    let mut header_vec = Vec::new();
    for header in headers {
        header_vec.push((header.field.as_str().as_str(), header.value.as_str()));
    }
    header_vec
}

fn parse_headers(headers: &[Header]) -> HeaderOptions {
    let mut options = HeaderOptions::default();

    for header in headers {
        if header.field.equiv(KEY_HEADER_NAME) {
            options.key = Some(header.value.as_str())
        } else if header.field.equiv(RELOAD_HEADER_NAME) {
            let value = header.value.as_str();
            if value == "1" || value == "true" {
                options.reload = true
            }
        } else if header.field.equiv(PATTERN_VALUE_HEADER_NAME) {
            options.pattern_value = Some(header.value.as_str())
        }
    }

    options
}

#[derive(Default)]
struct HeaderOptions<'a> {
    key: Option<&'a str>,
    pattern_value: Option<&'a str>,
    // Default for bool is false
    reload: bool,
}

enum HandleState<'a> {
    Pattern(&'a str),

    NotFound,
    BadRequest(String),
    Redirect(Cow<'a, str>),
    Response(DerivedResponse),
}

impl<'a> HandleState<'a> {
    fn redirect<S: Into<Cow<'a, str>>>(location: S) -> Self {
        HandleState::Redirect(location.into())
    }

    /// Whether we are in a finished, resolved state
    fn resolved(&self) -> bool {
        matches!(&self, Self::Redirect(_))
            || matches!(&self, Self::NotFound)
            || matches!(&self, Self::BadRequest(_))
            || matches!(&self, Self::Response(_))
    }

    fn unwrap_pattern(&self) -> &str {
        match &self {
            Self::Pattern(pattern) => pattern,
            _ => unreachable!("should only be unwrapped when it is pattern!")
        }
    }
}

struct HandleOptions<'a> {
    compile_path: &'a str,
    default_pattern: &'a str,
    sub_path: Option<&'a str>,
    repo_url: &'a str
}

fn handle_request_old<'a>(
    registry: &PluginRegistry,
    db_ref: &mut DatabaseRef,
    url: &'a str,
    header_options: &HeaderOptions,
    trust_key: Option<&str>,
    handle_options: &HandleOptions,
) -> Result<HandleState<'a>, Report> {
    // If loaded trust_key is none, we always trust, otherwise we must have that the key is provided in the header and equals the trust_key
    let trusted = trust_key.is_none()
        || header_options
            .key
            .zip(trust_key)
            .is_some_and(|(l, r)| l == r);

    let state = pattern_from_url(url, handle_options.default_pattern, handle_options.sub_path);

    let pattern = match state {
        HandleState::Pattern(pattern) => pattern,
        state => return Ok(state),
    };

    // If the header is set, we are trusted and it's valid format, we assume it's a valid commit and put it into the git ref store
    // This is the way to add refs for now and update 'main'
    if let Some(pattern_value) = header_options.pattern_value {
        if !is_hexadecimal(pattern_value) || pattern_value.len() != 40 {
            return Ok(HandleState::BadRequest(format!("header value {} is not a valid full commit hash, must be hexadecimal and length 40!", pattern_value)));
        }

        if trusted {
            // If trusted, we assume the pattern given is correct and we put it in the git ref store
            debug!("Inserting {pattern_value} at {pattern} in git ref store...");
            <DatabaseRef as GitRefStore>::insert(
                db_ref,
                handle_options.repo_url,
                pattern,
                Cow::Borrowed(CommitHash::from_str_unchecked(pattern_value)),
            )?;
        }
    }
    // Only allow disabling cache when trusted
    let use_cache = !header_options.reload || !trusted;
    debug!(
        "trusted={}, RELOAD={}, use_cache={}",
        trusted, header_options.reload, use_cache
    );
    let response = run_derive_response(
        registry,
        db_ref,
        handle_options.compile_path,
        handle_options.repo_url,
        use_cache,
        pattern,
    )?;

    if let Some(response) = response {
        Ok(HandleState::Response(response))
    } else {
        Ok(HandleState::NotFound)
    }
}

fn run_derive_response(
    registry: &PluginRegistry,
    db_ref: &mut DatabaseRef,
    subpath: &str,
    repo_url: &str,
    use_cache: bool,
    git_ref_or_hash: &str,
) -> Result<Option<DerivedResponse>, Report> {
    debug!("Running with pattern={git_ref_or_hash}");
    let commit_hash = {
        let opt = <DatabaseRef as GitRefStore>::get(db_ref, repo_url, git_ref_or_hash)?;
        opt.map(|cow| cow.into_owned())
    };

    let mut allow_exclusive = false;
    let address = if let Some(commit_hash) = &commit_hash {
        debug!(
            "Got commit_hash={} from git ref store.",
            commit_hash.as_str()
        );
        // We only allow exclusive operations if the commit hash comes from the git ref store, which can only be added to in trusted mode
        // This means that, at least for now, every allowed commit must have at least come from the git ref store once
        allow_exclusive = true;
        // If stored we trust it is a commit hash
        GitAddress::new_unchecked(repo_url, subpath, commit_hash.as_str())
    } else {
        let checked_commit = match CommitHash::try_from_str(git_ref_or_hash) {
            Ok(checked) => checked.as_str(),
            Err(e) => {
                info!("cannot be found: {}", e);
                return Ok(None);
            }
        };

        // Otherwise we check it here
        GitAddress::new_unchecked(repo_url, subpath, checked_commit)
    };
    debug!("address={address:?};allow_exclusive={allow_exclusive}");

    // Allow changing these and bring them outside this function
    let settings = &ServerSettingsView {
        store_dir: "./store".into(),
        verify_integrity: false,
    };
    match registry.derive_with(
        "compile_typst_main",
        settings,
        &address,
        use_cache,
        allow_exclusive,
        db_ref,
    ) {
        Ok(result) => Ok(Some(result)),
        Err(GitDeriveError::Absent(e)) => {
            info!("absent:{}", e);
            Ok(None)
        }
        r => Ok(Some(r?)),
    }
}

struct Config {
    hostname: String,
    port: u16,
    // repository_url: String,
    compilation_path: String,
    // store_path: Utf8PathBuf,
    // // Filename relative to compilation path
    // typst_input: String,
    // // Filename relative to compilation path, should include `.pdf` extension
    // typst_output: String,
    default_pattern: String,
    // Can consist of only one path without any `/`
    sub_path: Option<String>,
    repo_url: String
}

trait ParsedHeaders {
    type Parsed;

    fn parse(headers: Vec<(&str, &str)>) -> Self::Parsed;
}

pub struct ServerConfig<'a> {
    pub hostname: &'a str,
    pub port: u16,
}

// struct RequestSettings<'a> {
//     repo_url: &'a str,
//     relative_path: &'a str,
//     plugin_name: &'a str,
//     use_cache: bool,
//     mutate_store: bool
// }

// trait Handler {
//     type ParsedHeaders<'hd>;

//     fn parse_headers<'hd>(headers: Vec<(&str, &str)>) -> Self::ParsedHeaders<'hd>;

//     fn handle_url<'hd, 'st>(url: &str, parsed_headers: &Self::ParsedHeaders<'hd>) -> HandleState<'st>;

//     fn handle_pattern<'hd, 'st, E: Into<CacheErrorKind>>(registry: &PluginRegistry, pattern: &str, request_settings: &RequestSettings, git_ref_store: &mut impl GitRefGuardedStore, cache: &mut impl ResponseCache<E>) -> HandleState<'st> {
//         let guard = git_ref_store.read_guard().unwrap();

//         let commit = git_ref_store.get(request_settings.repo_url, pattern, &guard).unwrap();

//         let address = commit.map(|guarded| {
//             let commit_hash = guarded.get();
//             GitAddress::new_unchecked(request_settings.repo_url, request_settings.relative_path, commit_hash.as_str())
//         });

//         let r = if let Some(address) = address {
//             let response = registry.derive_with(request_settings.plugin_name, request_settings.server_settings, &address, request_settings.use_cache, allow_exclusive, cache).unwrap();

//         } else {
//             None
//         };

//         None
//     }
    
// }


pub trait RequestSettings {
    fn base(&self) -> Self;

    fn address<'a>(&'a self) -> Result<GitAddress<'a>, EarlyResolve<'a>>;

    fn plugin_name(&self) -> &str;

    fn use_cache(&self) -> bool;

    fn mutate_store(&self) -> bool;

    fn read_url<'url>(&mut self, url: &'url str) -> Result<(), EarlyResolve<'url>>;

    fn use_git_ref_store<'a>(&mut self, ref_store: &mut impl GitRefStore) -> Result<(), EarlyResolve<'a>>;

    fn read_method_headers<'a>(&mut self, method: &str, headers: Vec<(&str, &str)>) -> Result<(), EarlyResolve<'a>>;
}

#[derive(Clone)]
pub struct DefaultRequestSettings<'a> {
    repo_url: &'a str,
    git_subpath: &'a str,
    plugin_name: &'a str,
    default_path: &'a str,
    subpath: Option<&'a str>,
    trust_key: Option<&'a str>,
    use_cache: bool,
    mutate_store: bool,
    insert_pattern: Option<String>,
    commit: Option<CommitHashBuf>,
    pattern: Option<String>,
    trusted: bool,
}

pub struct RequestInitSettings<'a> {
    pub repo_url: &'a str,
    pub git_subpath: &'a str,
    pub plugin_name: &'a str,
    pub default_path: &'a str,
    pub subpath: Option<&'a str>,
    pub trust_key: Option<&'a str>,
}

impl<'a> DefaultRequestSettings<'a> {
    pub fn new(settings: &'a RequestInitSettings) -> Self {
        Self {
            repo_url: &settings.repo_url,
            git_subpath: &settings.git_subpath,
            plugin_name: &settings.plugin_name,
            default_path: &settings.default_path,
            subpath: settings.subpath,
            trust_key: settings.trust_key,
            use_cache: true,
            mutate_store: false,
            insert_pattern: None,
            commit: None,
            pattern: None,
            trusted: false
        }
    }
}

impl<'a> RequestSettings for DefaultRequestSettings<'a> {
    fn address<'b>(&'b self) -> Result<GitAddress<'b>, EarlyResolve<'b>> {
        if let Some(commit) = &self.commit {
            Ok(GitAddress::new_unchecked(&self.repo_url, &self.git_subpath, commit.as_str()))
        } else {
            Err(EarlyResolve::BadRequest("No commit could be found for provided pattern".to_owned()))
        }
    }

    fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    fn use_cache(&self) -> bool {
        self.use_cache
    }

    fn mutate_store(&self) -> bool {
        self.mutate_store
    }
    
    fn read_url<'url>(&mut self, url: &'url str) -> Result<(), EarlyResolve<'url>> {
        let pattern = parse_url(url, &self.default_path, self.subpath)?;

        self.pattern = Some(pattern.to_owned());

        Ok(())
    }
    
    fn use_git_ref_store<'b>(&mut self, ref_store: &mut impl GitRefStore) -> Result<(), EarlyResolve<'b>> {
        // If pattern is set that means we have some pattern we want to convert into a commit
        if let Some(pattern) = &self.pattern {
            // If insert_pattern was set (and we are trusted) that means we should add it to the ref store
            if self.insert_pattern.is_some() && self.trusted {
                let insert_pattern = self.insert_pattern.as_ref().unwrap();
                if !is_hexadecimal(&insert_pattern) || insert_pattern.len() != 40 {
                    return Err(EarlyResolve::BadRequest("Provided pattern value is not a valid commit hash!".to_owned()))
                }

                let commit_hash = CommitHashBuf::from_string_unchecked(pattern.to_owned());

                ref_store.insert(&self.repo_url, pattern.as_str(), Cow::Borrowed(commit_hash.borrow())).unwrap();

                // Only insert pattern if trusted and we can immediately set commit
                self.mutate_store = true;
                self.commit = Some(commit_hash);
            } else {
                let stored = ref_store.get(&self.repo_url, &pattern).unwrap();

                if let Some(stored) = stored {
                    self.mutate_store = true;
                    self.commit = Some(stored.into_owned());
                } else {
                    self.mutate_store = false;
                    // If we don't know the pattern and it's not a commit we surely don't set the commit
                    // TODO use some logic here to resolve it based on e.g. ls_remote
                    if !is_hexadecimal(&pattern) || pattern.len() != 40 {
                        return Err(EarlyResolve::BadRequest("Unknown pattern that is not a commit!".to_owned()))
                    }

                    self.commit = Some(CommitHashBuf::from_string_unchecked(pattern.to_owned()));
                }
            }
        }

        Ok(())
    }
    
    fn read_method_headers<'b>(&mut self, method: &str, headers: Vec<(&str, &str)>) -> Result<(), EarlyResolve<'b>> {
        if method != "GET" {
            return Err(EarlyResolve::BadRequest("Invalid method.".to_owned()))
        }

        for (key, value) in headers {
            if key == "borink-git-serve-key" {
                let trusted = if let Some(trust_key) = self.trust_key {
                    trust_key == value
                } else {
                    true
                };

                self.trusted = trusted;
            } else if key == "borink-git-no-cache" {
                if value == "1" || value == "true" {
                    self.use_cache = false;
                }
            } else if key == "borink-git-pattern-value" {
                self.insert_pattern = Some(value.to_owned())
            }
        }

        Ok(())
    }
    
    fn base(&self) -> Self {
        self.clone()
    }  
}

// fn derive_for_request<'a>(server_settings: &ServerSettingsView, settings: &'a impl RequestSettings, registry: &PluginRegistry, cache: &mut impl ResponseCache) -> Result<DerivedResponse, EarlyResolve<'a>> {
//     let address = settings.address()?;

//     match registry.derive_with(settings.plugin_name(), server_settings, &address, settings.use_cache(), settings.mutate_store(), cache) {
//         Ok(response) => Ok(response),
//         Err(GitDeriveError::Absent(e)) => Err(EarlyResolve::BadRequest(e.to_string())),
//         Err(e) => Err(EarlyResolve::BadRequest(e.to_string())),
//     }
// }

fn handle_request(request: &Request, server_settings: &ServerSettingsView, settings: &mut impl RequestSettings, ref_store: &mut impl GitRefStore, registry: &PluginRegistry, cache: &mut impl ResponseCache) -> Result<Response<Cursor<Vec<u8>>>, Report> {
    let headers = read_headers(request.headers());

    if let Err(err) = settings.read_method_headers(request.method().as_str(), headers) {
        return Ok(err.into_response())
    }

    if let Err(err) = settings.read_url(request.url()) {
        return Ok(err.into_response())
    }

    if let Err(err) = settings.use_git_ref_store(ref_store) {
        return Ok(err.into_response())
    }

    let address = match settings.address() {
        Ok(addr) => addr,
        Err(err) => {
            return Ok(err.into_response())
        }
    };

    let derived_response = match registry.derive_with(settings.plugin_name(), server_settings, &address, settings.use_cache(), settings.mutate_store(), cache) {
        Err(GitDeriveError::Absent(e)) => {
            return Ok(EarlyResolve::BadRequest(e.to_string()).into_response())
        },
        Err(e) => return Err(e.into()),
        Ok(response) => response
    };

    let mut response = Response::from_data(derived_response.bytes);
    for (k, v) in derived_response.headers {
        response.add_header(Header::from_bytes(k, v).unwrap());
    }

    Ok(response)

}

pub fn run_server(config: ServerConfig, server_settings: &ServerSettingsView, base_settings: &impl RequestSettings, 
    ref_store: &mut impl GitRefStore, registry: &PluginRegistry, cache: &mut impl ResponseCache) -> Result<(), Report> {
    let server = Server::http(format!("{}:{}", config.hostname, config.port)).unwrap();
    info!(
        "Server is running at {}:{}...",
        config.hostname, config.port
    );
    // let registry = PluginRegistry::new();
    // let db = Database::open("./db.sqlite".into())?;
    // let mut db_inst = db.prepare_new_ref()?;
    // let handle_options = HandleOptions {
    //     compile_path: &config.compOk(())ilation_path,
    //     default_pattern: &config.default_pattern,
    //     sub_path: config.sub_path.as_deref(),
    //     repo_url: &config.repo_url
    // };

    loop {
        let request = match server.recv() {
            Ok(request) => request,
            Err(e) => {
                error!("error receiving request: {}", e);
                continue;
            }
        };

        info!("HTTP {}: {}", request.method().as_str(), request.url());

        let response = match handle_request(&request, server_settings, &mut base_settings.base(), ref_store, registry, cache) {
            Ok(resp) => resp,
            Err(e) => {
                error!("{:#}", e);
                continue;
            }
        };

        request.respond(response)?;
    }
}

#[cfg(feature = "kv")]
pub fn default_server(config: ServerConfig, server_settings: &ServerSettingsView, init_settings: RequestInitSettings, db_path: &Utf8Path) -> Result<(), Report> {
    let settings = DefaultRequestSettings::new(&init_settings);
    let registry = PluginRegistry::new();

    let database = Database::open(db_path)?;

    let mut database_ref = database.prepare_new_ref()?;
    let mut database_ref_cache = database.prepare_new_ref()?;

    run_server(config, server_settings, &settings, &mut database_ref, &registry, &mut database_ref_cache)?;

    Ok(())
}