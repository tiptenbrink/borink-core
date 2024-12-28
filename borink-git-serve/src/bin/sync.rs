use borink_git_serve::client::sync_git_refs;

fn main() {
    sync_git_refs("https://github.com/tiptenbrink/tiauth.git", "http://localhost:8004").unwrap();
}