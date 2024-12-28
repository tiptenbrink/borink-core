use borink_git::{ls_remote, CommitHashBuf};
use color_eyre::Report;
use reqwest::Client;

async fn sync_reqs(base_url: &str, commits: Vec<(String, CommitHashBuf)>) {
    let client = Client::new();

    println!("{:?}", commits);
    //client.get("url")
}

pub fn sync_git_refs(repo_url: &str, sync_url: &str) -> Result<(), Report> {
    let refs = ls_remote(None, Some(repo_url), None)?;

    let rt = tokio::runtime::Builder::new_current_thread().build()?;

    rt.block_on(async {
        sync_reqs(sync_url, refs).await
    });

    Ok(())
}

