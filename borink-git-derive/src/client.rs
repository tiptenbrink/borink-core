use borink_git::{ls_remote, CommitHash, CommitHashBuf};
use color_eyre::Report;
use reqwest::{Client, StatusCode};
use tracing::{error, info};

async fn make_sync_request(client: &Client, base_url: &str, git_ref: &str, commit: &CommitHash, key: Option<&str>) -> Result<(), Report> {
    let url = format!("{base_url}/{git_ref}");

    let req = client
        .get(&url)
        .header("borink-git-pattern-value", commit.as_str());

    let req = if let Some(key) = key {
        req.header("borink-git-derive-key", key)
    } else {
        req
    };

    info!("Requesting from {} with headers", url);

    let res = req.send().await?;
    
    if res.status() != StatusCode::OK {
        error!(
            "response error: {:?}",
            res.text()
                .await
                .unwrap_or("could not parse response as text".to_owned())
        )
    }

    Ok(())
}

async fn sync_reqs(
    base_url: &str,
    commits: Vec<(String, CommitHashBuf)>,
    key: Option<&str>,
) -> Result<(), Report> {
    let client = Client::new();

    for (git_ref, commit) in commits {
        make_sync_request(&client, base_url, &git_ref, &commit, key).await?;

        let stripped_ref = if git_ref.starts_with("refs/tags/") {
            git_ref.strip_suffix("refs/tags/")
        } else if git_ref.starts_with("refs/heads/") {
            git_ref.strip_suffix("refs/heads/")
        } else {
            None
        };

        if let Some(stripped_ref) = stripped_ref {
            make_sync_request(&client, base_url, stripped_ref, &commit, key).await?;
        }
    }

    Ok(())
}

pub fn sync_git_refs(repo_url: &str, sync_url: &str, key: Option<&str>) -> Result<(), Report> {
    let refs = ls_remote(None, Some(repo_url), None)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build()?;

    //println!("{:?}", refs);

    rt.block_on(async { sync_reqs(sync_url, refs, key).await })?;

    Ok(())
}
