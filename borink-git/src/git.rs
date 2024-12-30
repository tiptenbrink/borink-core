use borink_error::{ContextSource, StringContext, WrapErrorWithContext};
use borink_process::ProcessError;
use camino::{Utf8Path, Utf8PathBuf};
use core::fmt::Debug;
use relative_path::{Component, RelativePath, RelativePathBuf};
use std::{
    borrow::Borrow, cmp, fs::{self, remove_dir_all, File}, io::{self, Error as IOError, Write}, path::Path
};
use thiserror::Error as ThisError;
use tracing::debug;

pub fn is_hexadecimal(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

#[derive(ThisError, Debug)]
pub enum GitError {
    #[error("git error not allowed: {0}")]
    NotAllowed(StringContext),
    #[error("git command failed with following output: {0}")]
    Failed(StringContext),
    #[error("process error trying to run Git! {0}")]
    Process(#[from] ContextSource<ProcessError>),
    #[error("error with the filesystem before running Git: {0}")]
    IO(#[from] ContextSource<IOError>),
    #[error("failed to parse Git URL to get name: {0}")]
    ParseURL(StringContext),
    #[error("failed to resolve pattern as commit: {0}")]
    InvalidPattern(StringContext),
    #[error("normalized subpath {0} is not a relative path inside the repository without '..' components")]
    InvalidPath(StringContext),
    // #[error("git absent error: {0}")]
    // Absent(StringContext),
}

/// This is a relative path that does contain any ".." or similar
#[derive(Debug)]
pub struct GitRelativePathBuf(RelativePathBuf);

impl GitRelativePathBuf {
    pub fn as_ref(&self) -> GitRelativePath<'_> {
        GitRelativePath(self.0.as_relative_path())
    }
}

#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct GitRepositoryUrl<'a>(&'a str);

impl<'a> GitRepositoryUrl<'a> {
    pub fn as_str(&self) -> &str {
        self.0
    }
}
// This is a relative path that does contain any ".." or similar
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct GitRelativePath<'a>(&'a RelativePath);

impl<'a> GitRelativePath<'a> {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ShaRef {
    pub sha: String,
    pub git_ref: String,
}

impl cmp::PartialOrd for ShaRef {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::Ord for ShaRef {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.git_ref.cmp(&other.git_ref)
    }
}

/// https://stackoverflow.com/a/65192210
fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn str_last_n(input: &str, n: usize) -> &str {
    let split_pos = input.char_indices().nth_back(n - 1).unwrap().0;
    &input[split_pos..]
}

/// Returns a name for a git URL
#[allow(dead_code)]
pub fn parse_url_name(url: &str) -> Result<String, GitError> {
    let url = url.strip_suffix('/').unwrap_or(url).to_owned();
    // We want the final part, after the slash, as the "file name"
    let split_parts: Vec<&str> = url.split('/').collect();

    // If last does not exist then the string is empty so invalid
    let last_part = *split_parts
        .last()
        .ok_or(GitError::ParseURL(url.clone().into()))?;

    // In case there is a file extension (such as `.git`), we don't want that part of the name
    let split_parts_dot: Vec<&str> = last_part.split('.').collect();
    let name = if split_parts_dot.len() <= 1 {
        // In this case no "." exists and we return just the entire "file name"
        last_part.to_owned()
    } else {
        // We get only the part that comes before the first .
        (*split_parts_dot
            .first()
            .ok_or(GitError::ParseURL(url.clone().into()))?)
        .to_owned()
    };

    Ok(name)
}

use sha2::{Digest, Sha256};

use crate::git_call::{checkout, commit_exists, repo_clone, repo_fetch};

/// This should only ever be a hexstring that represents a full 20-byte SHA
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct CommitHashBuf(String);

impl CommitHashBuf {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct CommitHash(str);

impl Borrow<CommitHash> for CommitHashBuf {
    fn borrow(&self) -> &CommitHash {
        CommitHash::from_str_unchecked(self.as_str())
    }
}

impl ToOwned for CommitHash {
    type Owned = CommitHashBuf;

    fn to_owned(&self) -> Self::Owned {
        CommitHashBuf::from_string_unchecked(self.as_str().to_owned())
    }
}

#[derive(Debug)]
pub struct GitAddress<'a> {
    pub repository_url: GitRepositoryUrl<'a>,
    pub subpath: GitRelativePath<'a>,
    pub commit_hash: &'a CommitHash,
}

impl<'a> GitAddress<'a> {
    pub fn new_unchecked(url: &'a str, subpath: &'a str, commit_hash: &'a str) -> GitAddress<'a> {
        GitAddress {
            repository_url: GitRepositoryUrl(url),
            subpath: GitRelativePath(RelativePath::new(subpath)),
            commit_hash: CommitHash::from_str_unchecked(commit_hash),
        }
    }
}

#[derive(ThisError, Debug)]
#[error("{0}")]
pub struct InvalidCommitHash(StringContext);

impl From<InvalidCommitHash> for GitError {
    fn from(value: InvalidCommitHash) -> Self {
        GitError::InvalidPattern(value.0)
    }
}

impl CommitHash {
    pub fn from_str_unchecked<S: AsRef<str> + ?Sized>(commit_str: &S) -> &Self {
        let p: *const str = std::ptr::from_ref(commit_str.as_ref());
        // SAFETY: We know CommitHash and str have the same layout, and from Rust reference we know pointer cast between unsized cast remains unchanged and metadata is preserved
        unsafe { &*(p as *const CommitHash) }
    }

    pub fn try_from_str(s: &str) -> Result<&Self, InvalidCommitHash> {
        if !is_hexadecimal(s) || s.len() != 40 {
            return Err(InvalidCommitHash(
                format!(
                    "{} is not hexadecimal and not length 40, invalid commit hash",
                    s
                )
                .into(),
            ));
        }

        Ok(Self::from_str_unchecked(s))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl CommitHashBuf {
    pub fn from_string_unchecked(commit_str: String) -> Self {
        Self(commit_str)
    }

    pub fn from_string_ref_unchecked(commit_str: &String) -> &Self {
        let p = std::ptr::from_ref(commit_str);
        let p_commit: *const CommitHashBuf = p.cast();
        // SAFETY: We know CommitHashBuf and String have the same layout, so the pointer constructed above is also valid
        unsafe { &*(p_commit) }

        // Note that we cannot do this with &str because we know nothing of its allocation and the capacity of the underlying String
    }
}

/// A single string that uniquely represents a [`GitAddress`], implemented as a hexadecimal
/// representation of a hashed [`GitAddress`].
#[derive(Eq, Hash, PartialEq, Clone)]
#[repr(transparent)]
pub struct StoreAddress(String);

impl StoreAddress {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<'a> From<&GitAddress<'a>> for StoreAddress {
    fn from(address: &GitAddress<'a>) -> Self {
        store_address(address)
    }
}

fn store_address(address: &GitAddress) -> StoreAddress {
    let mut hasher = Sha256::new();
    hasher.update(address.repository_url.0);
    hasher.update(&address.commit_hash.0);
    hasher.update(address.subpath.0.as_str());
    let hash = hasher.finalize();
    let hex = format!("{:x}", hash);

    StoreAddress(hex)
}

pub fn store_repo_path(
    repo_url: &GitRepositoryUrl,
    subpath: &GitRelativePath,
) -> GitRelativePathBuf {
    let mut hasher = Sha256::new();
    hasher.update(repo_url.0);
    hasher.update(subpath.0.as_str());
    let hash = hasher.finalize();
    let mut hex = format!("{:x}", hash);
    // We'll assume 24 chars is enough to ensure no duplicate project names
    // We want to keep them short to keep the paths short
    hex.truncate(24);

    // It's base64url so we know it's there's no '..' or similar
    GitRelativePathBuf(RelativePathBuf::from(hex))
}

fn store_repo_exists(
    store_dir: &Utf8Path,
    repo_url: &GitRepositoryUrl,
    subpath: &GitRelativePath,
    verify_integrity: bool,
) -> Result<GitState, GitError> {
    let store_repo_path = store_repo_path(repo_url, subpath);
    let store_repo_dir = store_dir.join(store_repo_path.0.as_str());

    if store_repo_dir.try_exists().map_err_with_context(format!(
        "failed to check existence of store repo dir {}",
        store_repo_dir
    ))? {
        if verify_integrity {
            unimplemented!("integrity verification not yet implemented!");
        }

        Ok(GitState::RepoExists { store_repo_dir })
    } else {
        Ok(GitState::RepoAbsent {
            store_repo_path,
            store_repo_dir,
        })
    }
}

fn clone_store_repo(
    store_dir: &Utf8Path,
    repo_url: &GitRepositoryUrl,
    subpath: &GitRelativePath,
    store_repo_path: GitRelativePathBuf,
    store_repo_dir: Utf8PathBuf,
) -> Result<GitState, GitError> {
    repo_clone(
        store_dir,
        &store_repo_path.as_ref(),
        repo_url.0,
        Some(subpath),
    )?;
    let metadata_path = store_repo_dir.join("dirg_repo_meta");
    let mut file = File::create(store_repo_dir.join("dirg_repo_meta"))
        .map_err_with_context("failed to create metadata file!")?;
    println!("file {:?}", metadata_path);

    let metadata = format!("url:{}\nsubpath:{}", repo_url.0, subpath.0.as_str());
    file.write_all(metadata.as_bytes())
        .map_err_with_context("failed to write to metadatafile!")?;

    Ok(GitState::RepoExists { store_repo_dir })
}

#[allow(dead_code)]
pub fn process_subpath(subpath: &str) -> Result<GitRelativePathBuf, GitError> {
    let path = RelativePath::new(subpath);
    let normalized = path.normalize();
    let contains_parent = normalized
        .components()
        .any(|p| matches!(p, Component::ParentDir));

    // We don't allow any '..' in the path
    if contains_parent {
        return Err(GitError::InvalidPath(normalized.as_str().into()));
    };

    // Normalized path also will not start with '/', we assume it's now safe to use
    Ok(GitRelativePathBuf(normalized))
}

#[derive(Debug)]
pub enum GitState {
    Start {},
    // Local states
    RequestRepo {},
    RepoExists {
        store_repo_dir: Utf8PathBuf,
    },
    RepoAbsent {
        store_repo_path: GitRelativePathBuf,
        store_repo_dir: Utf8PathBuf,
    },
    RequestAddress {
        store_repo_dir: Utf8PathBuf,
    },
    AddressAbsent {
        store_repo_dir: Utf8PathBuf,
    },
    // Exclusive states
    CreateRepo {
        store_repo_path: GitRelativePathBuf,
        store_repo_dir: Utf8PathBuf,
    },
    CreateAddress {
        store_repo_dir: Utf8PathBuf,
    },
    // Resolved
    Resolved(FinalResolved),
}

#[derive(Debug)]
pub enum FinalResolved {
    Path(Utf8PathBuf),
    Absent,
    // No more states left
    // Empty,
}

enum StateHandler {
    Local,
    Exclusive,
    Resolved,
}

impl GitState {
    fn handler(&self) -> StateHandler {
        match self {
            GitState::CreateRepo { .. } | GitState::CreateAddress { .. } => StateHandler::Exclusive,

            GitState::Start { .. }
            | GitState::RequestRepo { .. }
            | GitState::RepoExists { .. }
            | GitState::RepoAbsent { .. }
            | GitState::RequestAddress { .. }
            | GitState::AddressAbsent { .. } => StateHandler::Local,

            GitState::Resolved(_) => StateHandler::Resolved,
        }
    }

    fn unwrap_resolved(self) -> FinalResolved {
        match self {
            GitState::Resolved(resolved) => resolved,
            _ => panic!("cannot cast as resolved when not in resolved state!"),
        }
    }
}

pub trait Driver {
    fn drive(self, options: GetOptions, address: &GitAddress) -> Result<FinalResolved, GitError>
    where
        Self: Sized;
}

/// Various options for running `get_git_path`.
/// - `verify_integrity`: When using the already stored files for a repo or address, verify their integrity to ensure. Currently unimplemented.
/// - `mutate_store`: When set to `false`, the store is not allowed to be modified. In practice this means that it can only utilize files that already exist and it will not do any additional clones or checkouts.
/// - `store_dir`: the directory used to store all files.
pub struct GetOptions<'a> {
    verify_integrity: bool,
    mutate_store: bool,
    store_dir: &'a Utf8Path,
}

impl<'a> GetOptions<'a> {
    pub fn new(store_dir: &'a Utf8Path, mutate_store: bool, verify_integrity: bool) -> Self {
        Self {
            store_dir,
            mutate_store,
            verify_integrity,
        }
    }

    pub fn with_store_dir_mutate(store_dir: &'a Utf8Path, mutate_store: bool) -> Self {
        Self {
            // Will default to true once implemented
            verify_integrity: false,
            mutate_store,
            store_dir,
        }
    }
}

pub fn get_git_path_with_driver<D: Driver>(
    driver: D,
    options: GetOptions,
    address: &GitAddress,
) -> Result<FinalResolved, GitError> {
    driver.drive(options, address)
}

pub fn get_git_path(options: GetOptions, address: &GitAddress) -> Result<FinalResolved, GitError> {
    get_git_path_with_driver(SingleLoopDriver, options, address)
}

pub struct SingleLoopDriver;

impl Driver for SingleLoopDriver {
    fn drive(self, options: GetOptions, address: &GitAddress) -> Result<FinalResolved, GitError>
    where
        Self: Sized,
    {
        single_loop(
            options.store_dir,
            address,
            options.mutate_store,
            options.verify_integrity,
        )
    }
}

fn single_loop(
    store_dir: &Utf8Path,
    address: &GitAddress,
    allow_exclusive: bool,
    verify_integrity: bool,
) -> Result<FinalResolved, GitError> {
    let mut state = GitState::Start {};

    if allow_exclusive && !store_dir.exists() {
        debug!("Store dir does not exist, creating...");
        fs::create_dir_all(store_dir)
            .map_err_with_context(format!("failed to create store dir: {}", store_dir))?;
    }

    loop {
        match state.handler() {
            StateHandler::Local => {
                state = drive_local(
                    state,
                    address.commit_hash,
                    store_dir,
                    &address.repository_url,
                    &address.subpath,
                    verify_integrity,
                )?
            }
            StateHandler::Exclusive => {
                if !allow_exclusive {
                    return Err(GitError::NotAllowed(
                        format!(
                            "exclusive operation with current state {:?} not allowed",
                            state
                        )
                        .into(),
                    ));
                }

                state = drive_exclusive(
                    state,
                    address.commit_hash,
                    store_dir,
                    &address.repository_url,
                    &address.subpath,
                )?
            }
            StateHandler::Resolved => return Ok(state.unwrap_resolved()),
        }
    }
}

fn drive_local(
    git_state: GitState,
    commit: &CommitHash,
    store_dir: &Utf8Path,
    repo_url: &GitRepositoryUrl,
    subpath: &GitRelativePath,
    verify_integrity: bool,
) -> Result<GitState, GitError> {
    match git_state {
        GitState::Start {} => Ok(GitState::RequestRepo {}),
        // Either to RepoExists or RepoAbsent
        GitState::RequestRepo {} => {
            store_repo_exists(store_dir, repo_url, subpath, verify_integrity)
        }
        GitState::RepoExists { store_repo_dir } => Ok(GitState::RequestAddress { store_repo_dir }),
        GitState::RepoAbsent {
            store_repo_path,
            store_repo_dir,
        } => Ok(GitState::CreateRepo {
            store_repo_path,
            store_repo_dir,
        }),
        // Either to AddressAbsent or Resolved
        GitState::RequestAddress { store_repo_dir } => address_exists(
            store_dir,
            repo_url,
            store_repo_dir,
            commit,
            &GitRelativePath(subpath.0),
            verify_integrity,
        ),
        GitState::AddressAbsent { store_repo_dir } => {
            Ok(GitState::CreateAddress { store_repo_dir })
        }
        // Exclusive operations
        GitState::CreateRepo { .. } => panic!("This is an exclusive operation!"),
        GitState::CreateAddress { .. } => panic!("This is an exclusive operation!"),
        // Resolved operations
        GitState::Resolved(_) => panic!("This is a resolved operation!"),
    }
}

fn drive_exclusive(
    git_state: GitState,
    commit: &CommitHash,
    store_dir: &Utf8Path,
    repo_url: &GitRepositoryUrl,
    subpath: &GitRelativePath,
) -> Result<GitState, GitError> {
    match git_state {
        // Errors if repo cannot be cloned
        GitState::CreateRepo {
            store_repo_path,
            store_repo_dir,
        } => clone_store_repo(
            store_dir,
            repo_url,
            subpath,
            store_repo_path,
            store_repo_dir,
        ),
        // Either Resolved(Absent) or Resolved(Path)
        GitState::CreateAddress { store_repo_dir } => create_git_address(
            store_dir,
            repo_url,
            &GitRelativePath(subpath.0),
            commit,
            &store_repo_dir,
        ),
        // Local operations
        GitState::Start { .. } => panic!("This is a local operation!"),
        GitState::RequestRepo { .. } => panic!("This is a local operation!"),
        GitState::RepoExists { .. } => panic!("This is a local operation!"),
        GitState::RepoAbsent { .. } => panic!("This is a local operation!"),
        GitState::RequestAddress { .. } => panic!("This is a local operation!"),
        GitState::AddressAbsent { .. } => panic!("This is a local operation!"),
        // Resolved operations
        GitState::Resolved(_) => panic!("This is a resolved operation!"),
    }
}

fn create_git_address(
    store_dir: &Utf8Path,
    repository_url: &GitRepositoryUrl,
    subpath: &GitRelativePath,
    commit_hash: &CommitHash,
    store_repo_dir: &Utf8Path,
) -> Result<GitState, GitError> {
    let store_address = store_address(&GitAddress {
        commit_hash,
        repository_url: repository_url.clone(),
        subpath: subpath.clone(),
    });
    let target_dir = store_dir.join("c").join(&store_address.0);

    // Update the repository if it doesn't exist
    // TODO add option to never fetch
    if !commit_exists(store_repo_dir, commit_hash)? {
        repo_fetch(store_repo_dir)?;

        if !commit_exists(store_repo_dir, commit_hash)? {
            // If it still doesn't exist, we know the commit doesn't exist on the remote either
            return Ok(GitState::Resolved(FinalResolved::Absent));
        }
    }

    // We copy the original repository so that the original one remains in the same state
    copy_dir_all(store_repo_dir, &target_dir)
        .map_err_with_context("error copying main repository before checkout.".to_owned())?;
    // Error checking out new commit.
    checkout(&target_dir, &commit_hash.0)?;
    remove_dir_all(target_dir.join(".git"))
        .map_err_with_context("error removing .git directory.".to_owned())?;

    let target_dir_subpath = target_dir.join(subpath.0.as_str());

    let mut file = File::create(target_dir_subpath.join("dirg_path_meta"))
        .map_err_with_context("failed to create metadata file!")?;
    let metadata = format!(
        "commit:{}\nrepo:{:?}\npath:{:?}",
        &commit_hash.0, &repository_url.0, &subpath.0
    );
    file.write_all(metadata.as_bytes())
        .map_err_with_context("failed to write to metadatafile!")?;

    Ok(GitState::Resolved(FinalResolved::Path(target_dir_subpath)))
}

fn address_exists(
    store_dir: &Utf8Path,
    repository_url: &GitRepositoryUrl,
    store_repo_dir: Utf8PathBuf,
    commit_hash: &CommitHash,
    subpath: &GitRelativePath,
    verify_integrity: bool,
) -> Result<GitState, GitError> {
    let address = GitAddress {
        repository_url: repository_url.clone(),
        commit_hash,
        subpath: subpath.clone(),
    };

    let store_address = store_address(&address);

    let target_dir = store_dir.join("c").join(&store_address.0);

    debug!("Checking for address {:?}", target_dir);
    if target_dir.exists() {
        if verify_integrity {
            unimplemented!("integrity verification not yet implemented!");
        }

        let target_dir_subpath = target_dir.join(address.subpath.0.as_str());
        debug!(
            "target address already exists for store address, returning path {}",
            target_dir_subpath
        );

        Ok(GitState::Resolved(FinalResolved::Path(target_dir_subpath)))
    } else {
        Ok(GitState::AddressAbsent { store_repo_dir })
    }
}
