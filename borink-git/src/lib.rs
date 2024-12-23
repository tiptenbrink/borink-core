mod git;
mod git_call;

pub use git::{get_git_path, get_git_path_with_driver, GetOptions, SingleLoopDriver};
pub use git::GitAddress;
pub use git::GitError;
pub use git::FinalResolved;
pub use git::{CommitHash, CommitHashBuf, GitRelativePath, GitRelativePathBuf, GitRepositoryUrl};

pub use git_call::{checkout, commit_exists, repo_clone, ls_remote, repo_fetch, run_git};