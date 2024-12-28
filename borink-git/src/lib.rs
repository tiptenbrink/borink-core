mod git;
mod git_call;
mod git_ref;

pub use git::FinalResolved;
pub use git::GitAddress;
pub use git::GitError;
pub use git::{get_git_path, get_git_path_with_driver, GetOptions, SingleLoopDriver};
pub use git::{
    is_hexadecimal, CommitHash, CommitHashBuf, GitRelativePath, GitRelativePathBuf,
    GitRepositoryUrl, StoreAddress,
};

pub use git_call::{checkout, commit_exists, ls_remote, repo_clone, repo_fetch, run_git};

pub use git_ref::GitRefStore;

#[cfg(feature = "guarded")]
pub use git_ref::guarded::{GitRefGuardedStore, ReadGuard};

#[cfg(feature = "redb")]
pub use git_ref::guarded::redb::Store;

#[cfg(feature = "papaya")]
pub use git_ref::guarded::papaya::ConcurrentMap;
