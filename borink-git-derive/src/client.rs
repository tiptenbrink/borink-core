use borink_git::{ls_remote, CommitHashBuf};
use color_eyre::Report;
use reqwest::{Client, StatusCode};
use tracing::{error, info};

async fn sync_reqs(base_url: &str, commits: Vec<(String, CommitHashBuf)>, key: Option<&str>) -> Result<(), Report> {
    let client = Client::new();

    for (git_ref, commit) in commits {
        let url = format!("{base_url}/{git_ref}");

        info!("Requesting from {}", url);

        let req = client.get(url)
            .header("borink-git-pattern-value", commit.as_str());

        let req = if let Some(key) = key {
            req.header("borink-git-derive-key", key)
        } else {
            req
        };

        let res = req.send().await?;
        if res.status() != StatusCode::OK {
            error!("response error: {:?}", res.text().await.unwrap_or("could not parse response as text".to_owned()))
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

    rt.block_on(async {
        sync_reqs(sync_url, refs, key).await
    })?;

    Ok(())
}

