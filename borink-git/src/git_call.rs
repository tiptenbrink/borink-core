use borink_error::ErrorWithContext;
use borink_process::process_complete_output;
use camino::{Utf8Path, Utf8PathBuf};
use spinoff::{spinners, Spinner};
use tracing::debug;

use crate::git::{CommitHash, CommitHashBuf, GitError, GitRelativePath, ShaRef};
use core::fmt::Debug;
use std::{env::current_dir, ffi::OsStr};

pub fn run_git<S: AsRef<OsStr> + Debug>(
    working_dir: &Utf8Path,
    args: Vec<S>,
    op_name: &'static str,
) -> Result<String, GitError> {
    let git_out = process_complete_output(working_dir, "git", args);

    match git_out {
        Ok(out) => {
            if out.exit.success() {
                Ok(out.out)
            } else {
                Err(GitError::Failed(out.out.into()))
            }
        }
        Err(err) => Err(err
            .with_context(format!("Git operation {} failed.", op_name))
            .into()),
    }
}

/// Clones a repository using --filter:tree:0, i.e. a treeless clone which means all commits are downloaded but no blobs or clones.
/// It ensures the repository is put in sparse mode and nothing is checked out. We don't use a shallow clone because we will always
/// need some commit (and not necessarily the latest one) and Git behaves better when commit history is there.
pub fn repo_clone(
    current_dir: &Utf8Path,
    directory: &GitRelativePath,
    repository: &str,
    subpath: Option<&GitRelativePath>,
) -> Result<(), GitError> {
    debug!(
        "Cloning repository {:?} directory at target {:?}",
        repository, directory
    );
    let mut sp = Spinner::new(spinners::Line, "Cloning repository...", None);

    let clone_args = vec![
        "clone",
        "--filter=tree:0",
        "--sparse",
        "--no-checkout",
        repository,
        directory.as_str(),
    ];

    let a = run_git(current_dir, clone_args, "partial sparse clone").inspect_err(|_| {
        sp.fail("Failed!");
    })?;

    sp.success("Repository cloned!");
    println!("msg: {}", a);
    let mut sp = Spinner::new(spinners::Line, "Doing sparse checkout...", None);
    let target_dir = current_dir.join(directory.as_str());

    let all_dirs_args = vec!["sparse-checkout", "disable"];

    let checkout_args = if let Some(subpath) = subpath {
        let subpath_str = subpath.as_str();
        if subpath_str.is_empty() {
            all_dirs_args
        } else {
            vec![
                "sparse-checkout",
                "set",
                "--cone",
                "--sparse-index",
                "--end-of-options",
                subpath_str,
            ]
        }
    } else {
        all_dirs_args
    };
    run_git(&target_dir, checkout_args, "sparse checkout cone").inspect_err(|_| {
        sp.fail("Failed!");
    })?;
    sp.success("Sparse checkout success!");

    Ok(())
}

pub fn repo_fetch(repo_dir: &Utf8Path) -> Result<(), GitError> {
    let mut sp = Spinner::new(spinners::Line, "Running git fetch...", None);

    run_git(repo_dir, vec!["fetch"], "fetch").inspect_err(|_| {
        sp.fail("Failed!");
    })?;

    sp.success("Fetched!");

    Ok(())
}

pub fn checkout(repo_dir: &Utf8Path, checkout_sha: &str) -> Result<(), GitError> {
    let mut sp = Spinner::new(spinners::Line, "Checking out...", None);

    let clone_args = vec!["checkout", checkout_sha];
    run_git(repo_dir, clone_args, "checkout").inspect_err(|_| {
        sp.fail("Failed!");
    })?;

    sp.success("Checked out!");

    Ok(())
}

/// Returns `true` in case the commit exists. Note that also unique prefixes of commits will return true.
pub fn commit_exists(repo_dir: &Utf8Path, commit: &CommitHash) -> Result<bool, GitError> {
    debug!(
        "using git cat-file -e to check if commit {} exists.",
        &commit.as_str()
    );

    let mut sp = Spinner::new(spinners::Line, "Checking if commmit exists...", None);

    // The '-e' option ensures no output is generated, it's just the exist status which indicates whether it exists or not
    // That makes it quite fast
    let result = match run_git(
        repo_dir,
        vec!["cat-file", "-e", &commit.as_str()],
        "cat-file commit",
    ) {
        Ok(_) => Ok(true),
        Err(GitError::Failed(_)) => Ok(false),
        Err(e) => {
            sp.fail("Failed!");
            Err(e)
        }
    }?;

    sp.success("Checked for commit existence!");

    Ok(result)
}



/// This function uses some simple parsing of `git ls-remote origin` to determine the up-to-date git commit hashes for a pattern
/// These patterns can be branches or tags or other refs
/// If `remote` is given as None, it will use `origin` for the Git repository in the given `repo_dir`. It's possible to provide an url. Guaranteed to provide a vector sorted by the first tuple element (the ref).
pub fn ls_remote(repo_dir: Option<&Utf8Path>, remote: Option<&str>, pattern: Option<&str>) -> Result<Vec<(String, CommitHashBuf)>, GitError> {
    let mut sp = Spinner::new(spinners::Line, "Getting commit hash from remote...", None);

    let mut args = vec!["ls-remote"];
    if let Some(remote) = remote {
        args.push(remote);
    } else {
        args.push("origin");
    }
    if let Some(pattern) = pattern {
        args.push(pattern);
    }
    let mut dir: Option<Utf8PathBuf> = None;
    if repo_dir.is_none() {
        dir = Some(current_dir().unwrap().try_into().unwrap());
    };
    let out = run_git(
        repo_dir.unwrap_or(&dir.unwrap()),
        args,
        "ls-remote origin to get commit from pattern",
    )
    .inspect_err(|_| {
        sp.fail("Failed!");
    })?;

    sp.success("Got commit hashes from remote!");

    // `git ls-remote` returns a list of references and associated commit hashes in the format:
    // <commit> TAB <ref> newline
    // See https://git-scm.com/docs/git-ls-remote

    let out_trimmed = out.trim();
    let lines: Vec<&str> = match out_trimmed {
        // Ensure empty string is mapped to empty vec
        "" => vec![],
        out_trimmed => out_trimmed.split('\n').collect(),
    };

    let mut sha_refs = lines
        .into_iter()
        .map(|s| {
            let spl: Vec<&str> = s.split_whitespace().collect();
            // Each line should consist of the commit, a tab (whitespace), and the ref
            if spl.len() != 2 {
                return Err(GitError::Failed(
                    format!("ls-remote returned invalid result: {}", &out).into(),
                ));
            }

            let sha = spl[0].to_owned();
            let git_ref = spl[1].to_owned();

            Ok(ShaRef { sha, git_ref })
        })
        .collect::<Result<Vec<ShaRef>, GitError>>()?;

    sha_refs.retain(|sr| {
        // We don't care about the remotes of our remote
        !(*sr.git_ref).contains("refs/remotes")
    });

    // Suppose a list of refs like (would not be necessarily sorted):
    // ab
    // aq
    // bd
    // bd^{}
    // fg
    // zsdf
    // zsdf^{}

    sha_refs.sort();
    // They are now sorted in ascending order like above
    // We reverse them because we pop from the vector so go in reverse order
    sha_refs.reverse();
    // So we now have zsdf^{}, then zsdf, ..., ab

    let mut out = Vec::new();

    if sha_refs.is_empty() {
        return Ok(out)
    }

    // We know there's at least one element, so we can pop it
    // This would be ad in our example
    let mut current = sha_refs.pop().unwrap();
    for mut r in sha_refs {
        // If our new value starts with the same ref and ends with ^{}
        // Then we want the ref name without the ^{} but the peeled ref sha
        // In example first happens when current='bd', r='bd^{}'
        if r.git_ref.starts_with(&current.git_ref) && r.git_ref.ends_with("^{}") {
            // We keep the current's ref, but set it to the peeled's sha
            current.sha = r.sha;
        // In our example first this would be the case when we get aq
        } else {
            std::mem::swap(&mut current, &mut r);
            // Now current will have the new value, while r will have the old one
            // So in example current='aq', r='ab'
            // We then push the previous one to the vec, so 'ab' is pushed
            out.push((r.git_ref, CommitHashBuf::from_string_unchecked(r.sha)));
        }        
    }
    // We always push the previous, so we need to still push current
    // Also if there is just one this would be necessary
    out.push((current.git_ref, CommitHashBuf::from_string_unchecked(current.sha)));

    Ok(out)

    // let commit = if sha_refs.is_empty() {
    //     return Ok(None);

    //     // // FIXME, maybe use `git rev-list` and search all commits to also allow partial matches?
    //     // // Update repo to ensure we have all the commits
    //     // git_fetch(repo_dir)?;

    //     // let mut sp = Spinner::new(
    //     //     spinners::Line,
    //     //     "Running rev-parse to get full commit...",
    //     //     None,
    //     // );

    //     // let commit_result = run_git(
    //     //     repo_dir,
    //     //     vec!["rev-parse", pattern],
    //     //     "rev-parse to get full commit",
    //     // )
    //     // .map_err(|e| {
    //     //     sp.fail("Failed!");
    //     //     e
    //     // })?;

    //     // sp.success("Got commit hashes from remote!");

    //     // commit_result
    // } else if sha_refs.len() >= 2 && sha_refs.iter().all(|s| s.sha == sha_refs[0].sha) {
    //     // All the same, so no ambiguity
    //     sha_refs[0].sha.to_owned()
    // } else if sha_refs.len() == 2 {
    //     // We want the one with ^{}
    //     if sha_refs[0].git_ref.ends_with("^{}") {
    //         sha_refs[0].sha.to_owned()
    //     } else if sha_refs[1].git_ref.ends_with("^{}") {
    //         sha_refs[1].sha.to_owned()
    //     } else {
    //         return Err(GitError::Failed(
    //             format!(
    //                 "could not choose tag from two options for ls-remote: {:?}",
    //                 &sha_refs
    //             )
    //             .into(),
    //         ));
    //     }
    // } else if sha_refs.len() == 1 {
    //     sha_refs[0].sha.to_owned()
    // } else {
    //     return Err(GitError::Failed(
    //         format!(
    //             "pattern is not specific enough, cannot determine commit for {}",
    //             pattern
    //         )
    //         .into(),
    //     ));
    // };

    // debug!("git commit from ls-remote={}", commit);
    // Ok(Some(CommitHashBuf::from_string_unchecked(commit)))
}
