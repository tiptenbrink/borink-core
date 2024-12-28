use crate::derive::GitDeriveError;
use crate::derive::{PluginRegistry, ResponseCache, ServerSettingsView};
use borink_git::{is_hexadecimal, CommitHashBuf, GitAddress, GitRefStore};
use borink_kv::Database;
use camino::Utf8Path;
use color_eyre::Report;
use std::borrow::{Borrow, Cow};
use std::io::Cursor;
use tiny_http::{Header, Request, Response, Server};
use tracing::{debug, error, info};

fn redirect(location: &str) -> Response<Cursor<Vec<u8>>> {
    Response::from_data([])
        .with_status_code(303)
        .with_header(Header::from_bytes("Location", location).unwrap())
}

#[derive(Debug)]
pub enum EarlyResolve<'a> {
    NotFound,
    BadRequest(String),
    Redirect(Cow<'a, str>),
}

impl<'a> EarlyResolve<'a> {
    fn redirect<S: Into<Cow<'a, str>>>(location: S) -> Self {
        Self::Redirect(location.into())
    }

    fn response(&self) -> Response<Cursor<Vec<u8>>> {
        debug!("Early resolve {:?}, returning response...", &self);
        match &self {
            EarlyResolve::NotFound => Response::from_data([]).with_status_code(404),
            EarlyResolve::Redirect(location) => redirect(location.as_ref()),
            EarlyResolve::BadRequest(message) => {
                Response::from_string(message).with_status_code(400)
            }
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
            return Err(EarlyResolve::NotFound);
        }

        // We have at least ["?", "<sub_path>"] now

        if url_parts.len() == 2 || url_parts[3].is_empty() {
            let location = format!("/{}/{}", sub_path, default_pattern);
            return Err(EarlyResolve::redirect(location));
        }

        if url_parts.len() > 3 {
            let location = format!("/{}/{}", sub_path, url_parts[2]);
            return Err(EarlyResolve::redirect(location));
        }

        url_parts[2]
    } else {
        // We expect a valid path to look something like ["", "<pattern>"]

        if url_parts.len() < 2 || url_parts[1].is_empty() {
            let location = format!("/{}", default_pattern);
            return Err(EarlyResolve::redirect(location));
        }

        // We have at least ["?", "<non_empty>"] now

        if url_parts.len() > 2 {
            let location = format!("/{}", url_parts[1]);
            return Err(EarlyResolve::redirect(location));
        }

        url_parts[1]
    };

    Ok(pattern_path)
}

fn read_headers(headers: &[tiny_http::Header]) -> Vec<(&str, &str)> {
    let mut header_vec = Vec::new();
    for header in headers {
        header_vec.push((header.field.as_str().as_str(), header.value.as_str()));
    }
    header_vec
}

pub struct ServerConfig<'a> {
    pub hostname: &'a str,
    pub port: u16,
}

pub trait RequestSettings {
    fn base(&self) -> Self;

    fn address(&self) -> Result<GitAddress<'_>, EarlyResolve<'_>>;

    fn plugin_name(&self) -> &str;

    fn use_cache(&self) -> bool;

    fn mutate_store(&self) -> bool;

    fn read_url<'url>(&mut self, url: &'url str) -> Result<(), EarlyResolve<'url>>;

    fn use_git_ref_store<'a>(
        &mut self,
        ref_store: &mut impl GitRefStore,
    ) -> Result<(), EarlyResolve<'a>>;

    fn read_method_headers<'a>(
        &mut self,
        method: &str,
        headers: Vec<(&str, &str)>,
    ) -> Result<(), EarlyResolve<'a>>;
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
            repo_url: settings.repo_url,
            git_subpath: settings.git_subpath,
            plugin_name: settings.plugin_name,
            default_path: settings.default_path,
            subpath: settings.subpath,
            trust_key: settings.trust_key,
            use_cache: true,
            mutate_store: false,
            insert_pattern: None,
            commit: None,
            pattern: None,
            trusted: false,
        }
    }
}

impl<'a> RequestSettings for DefaultRequestSettings<'a> {
    fn address(&self) -> Result<GitAddress<'_>, EarlyResolve<'_>> {
        if let Some(commit) = &self.commit {
            Ok(GitAddress::new_unchecked(
                self.repo_url,
                self.git_subpath,
                commit.as_str(),
            ))
        } else {
            Err(EarlyResolve::BadRequest(
                "No commit could be found for provided pattern".to_owned(),
            ))
        }
    }

    fn plugin_name(&self) -> &str {
        self.plugin_name
    }

    fn use_cache(&self) -> bool {
        self.use_cache
    }

    fn mutate_store(&self) -> bool {
        self.mutate_store
    }

    fn read_url<'url>(&mut self, url: &'url str) -> Result<(), EarlyResolve<'url>> {
        let pattern = parse_url(url, self.default_path, self.subpath)?;

        self.pattern = Some(pattern.to_owned());

        Ok(())
    }

    fn use_git_ref_store<'b>(
        &mut self,
        ref_store: &mut impl GitRefStore,
    ) -> Result<(), EarlyResolve<'b>> {
        debug!("Reading from ref store implemented using {}...", ref_store.name());
        // If pattern is set that means we have some pattern we want to convert into a commit
        if let Some(pattern) = &self.pattern {
            // If insert_pattern was set (and we are trusted) that means we should add it to the ref store
            if self.insert_pattern.is_some() && self.trusted {
                let insert_pattern = self.insert_pattern.as_ref().unwrap();
                if !is_hexadecimal(insert_pattern) || insert_pattern.len() != 40 {
                    return Err(EarlyResolve::BadRequest(
                        "Provided pattern value is not a valid commit hash!".to_owned(),
                    ));
                }

                let commit_hash = CommitHashBuf::from_string_unchecked(pattern.to_owned());

                ref_store
                    .insert(
                        self.repo_url,
                        pattern.as_str(),
                        Cow::Borrowed(commit_hash.borrow()),
                    )
                    .unwrap();

                // Only insert pattern if trusted and we can immediately set commit
                self.mutate_store = true;
                self.commit = Some(commit_hash);
            } else {
                let stored = ref_store.get(self.repo_url, pattern).unwrap();

                if let Some(stored) = stored {
                    self.mutate_store = true;
                    self.commit = Some(stored.into_owned());
                } else {
                    self.mutate_store = false;
                    // If we don't know the pattern and it's not a commit we surely don't set the commit
                    // TODO use some logic here to resolve it based on e.g. ls_remote
                    if !is_hexadecimal(pattern) || pattern.len() != 40 {
                        return Err(EarlyResolve::BadRequest(
                            format!("Unknown pattern {} that is not a commit!", pattern),
                        ));
                    }

                    self.commit = Some(CommitHashBuf::from_string_unchecked(pattern.to_owned()));
                }
            }
        }

        Ok(())
    }

    fn read_method_headers<'b>(
        &mut self,
        method: &str,
        headers: Vec<(&str, &str)>,
    ) -> Result<(), EarlyResolve<'b>> {
        if method != "GET" {
            return Err(EarlyResolve::BadRequest("Invalid method.".to_owned()));
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

fn handle_request(
    request: &Request,
    server_settings: &ServerSettingsView,
    settings: &mut impl RequestSettings,
    ref_store: &mut impl GitRefStore,
    registry: &PluginRegistry,
    cache: &mut impl ResponseCache,
) -> Result<Response<Cursor<Vec<u8>>>, Report> {
    let headers = read_headers(request.headers());
    debug!("Reading headers into settings...");
    if let Err(err) = settings.read_method_headers(request.method().as_str(), headers) {
        return Ok(err.response());
    }

    debug!("Reading url into settings...");
    if let Err(err) = settings.read_url(request.url()) {
        return Ok(err.response());
    }

    debug!("Reading Git ref store into settings...");
    if let Err(err) = settings.use_git_ref_store(ref_store) {
        return Ok(err.response());
    }

    debug!("Determining Git address...");
    let address = match settings.address() {
        Ok(addr) => addr,
        Err(err) => return Ok(err.response()),
    };

    let derived_response = match registry.derive_with(
        settings.plugin_name(),
        server_settings,
        &address,
        settings.use_cache(),
        settings.mutate_store(),
        cache,
    ) {
        Err(GitDeriveError::Absent(e)) => {
            return Ok(EarlyResolve::BadRequest(e.to_string()).response())
        }
        Err(e) => return Err(e.into()),
        Ok(response) => response,
    };

    let mut response = Response::from_data(derived_response.bytes);
    for (k, v) in derived_response.headers {
        response.add_header(Header::from_bytes(k, v).unwrap());
    }

    Ok(response)
}

pub fn run_server(
    config: ServerConfig,
    server_settings: &ServerSettingsView,
    base_settings: &impl RequestSettings,
    ref_store: &mut impl GitRefStore,
    registry: &PluginRegistry,
    cache: &mut impl ResponseCache,
) -> Result<(), Report> {
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

        let response = match handle_request(
            &request,
            server_settings,
            &mut base_settings.base(),
            ref_store,
            registry,
            cache,
        ) {
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
pub fn default_server(
    config: ServerConfig,
    server_settings: &ServerSettingsView,
    init_settings: RequestInitSettings,
    db_path: &Utf8Path,
) -> Result<(), Report> {
    let settings = DefaultRequestSettings::new(&init_settings);
    let registry = PluginRegistry::new();

    let database = Database::open(db_path)?;

    let mut database_ref = database.prepare_new_ref()?;
    let mut database_ref_cache = database.prepare_new_ref()?;

    run_server(
        config,
        server_settings,
        &settings,
        &mut database_ref,
        &registry,
        &mut database_ref_cache,
    )?;

    Ok(())
}
