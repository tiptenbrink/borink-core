//! This module provides functionality to translate references/tags/branches/versions (everything that is not an exact commit id) to commit id's. From now on we will just call these git refs, which is pretty close to the proper Git terminology.

use std::{borrow::{Borrow, Cow}, collections::HashMap, convert::Infallible};

use crate::{CommitHash, CommitHashBuf};

pub trait GitRefStore {
    // If we don't put the 'b bound on the error, it could maybe reference self, here we require it must
    // at least outlive the reference to self, which should be plenty flexible
    /// Get a CommitHash from the store, which depending on the implementation can be either owned
    /// or borrowed from the store. Can fail with an implementation-specific error.
    fn get<'slf, 'err: 'slf>(&'slf self, repo_url: &str, git_ref: &str) -> Result<Option<Cow<'slf, CommitHash>>, impl core::error::Error + 'err>;

    fn insert<'slf, 'err: 'slf, 'c>(&'slf mut self, repo_url: &str, git_ref: &str, commit_hash: Cow<'c, CommitHash>) -> Result<(), impl core::error::Error + 'err>;

    fn git_ref_key(repo_url: &str, git_ref: &str) -> String {
        format!("borink-git-ref:{repo_url}:{git_ref}")
    }
}

impl GitRefStore for HashMap<String, CommitHashBuf> {
    fn get<'slf, 'err: 'slf>(&'slf self, repo_url: &str, git_ref: &str) -> Result<Option<Cow<'slf, CommitHash>>, impl core::error::Error + 'err> {
        let opt = self
        .get(Self::git_ref_key(repo_url, git_ref).as_str());
        let cow = opt.map(|c| Cow::Borrowed(c.borrow()));
        Ok::<_, Infallible>(cow)
    }

    fn insert<'slf, 'err: 'slf, 'c>(
        &'slf mut self,
        repo_url: &str,
        git_ref: &str,
        commit_hash: Cow<'c, CommitHash>,
    ) -> Result<(), impl core::error::Error + 'err> {
        self.insert(Self::git_ref_key(repo_url, git_ref), commit_hash.into_owned());

        Ok::<_, Infallible>(())
    }
}

#[cfg(feature = "kv")]
use borink_kv::{DatabaseRef, KvError, KvMetaValue};

#[cfg(feature = "kv")]
impl<'rf> GitRefStore for DatabaseRef<'rf> {
    fn get<'slf, 'err: 'slf>(&'slf self, repo_url: &str, git_ref: &str) -> Result<Option<Cow<'slf, CommitHash>>, impl core::error::Error + 'err> {
        let opt = self.get(Self::git_ref_key(repo_url, git_ref).as_bytes())?;

        let cow = opt.map(|KvMetaValue { value, .. }| {
            let c = CommitHashBuf::from_string_unchecked(String::from_utf8(value).unwrap());
            Cow::Owned(c)
        });

        Ok::<_, KvError>(cow)
    }

    fn insert<'slf, 'err: 'slf, 'c>(
        &'slf mut self,
        repo_url: &str,
        git_ref: &str,
        commit_hash: Cow<'c, CommitHash>,
    ) -> Result<(), impl core::error::Error + 'err> {
        let meta = Vec::new();

        DatabaseRef::insert(
            self,
            Self::git_ref_key(repo_url, git_ref).as_bytes(),
            &meta,
            commit_hash.as_bytes(),
        )
    }
}

pub trait ReadGuard<'guard, T: ?Sized> {
    fn get(&'guard self) -> &'guard T;
}

pub trait GitRefGuardedStore {
    type GuardToken<'guard> where Self: 'guard;
    type ReadGuardType<'guard>: ReadGuard<'guard, CommitHash> where Self: 'guard;

    // If we don't put the 'err bound on the error, it could maybe reference self, here we require it must
    // at least outlive the reference to self, which should be plenty flexible
    fn get<'store: 'guard, 'err: 'store, 'guard>(&'store self, repo_url: &str, git_ref: &str, guard: &'guard Self::GuardToken<'guard>) -> Result<Option<Self::ReadGuardType<'guard>>, impl core::error::Error + 'err>;

    fn read_guard<'store: 'guard, 'err: 'store, 'guard>(&'store self) -> Result<Self::GuardToken<'guard>, impl core::error::Error + 'err>;

    fn insert<'store, 'err: 'store, 'c>(&'store mut self, repo_url: &str, git_ref: &str, commit_hash: std::borrow::Cow<'c, crate::CommitHash>) -> Result<(), impl core::error::Error + 'err>;

    fn git_ref_key(repo_url: &str, git_ref: &str) -> String {
        format!("borink-git-ref:{repo_url}:{git_ref}")
    }
}


