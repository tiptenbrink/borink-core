//! This module provides functionality to translate references/tags/branches/versions (everything that is not an exact commit id) to commit id's. From now on we will just call these git refs, which is pretty close to the proper Git terminology.

use std::{
    borrow::{Borrow, Cow},
    collections::HashMap,
    convert::Infallible,
};

use crate::{CommitHash, CommitHashBuf};

pub trait GitRefStore {
    fn name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    // If we don't put the 'b bound on the error, it could maybe reference self, here we require it must
    // at least outlive the reference to self, which should be plenty flexible
    /// Get a CommitHash from the store, which depending on the implementation can be either owned
    /// or borrowed from the store. Can fail with an implementation-specific error.
    fn get<'slf, 'err: 'slf>(
        &'slf self,
        repo_url: &str,
        git_ref: &str,
    ) -> Result<Option<Cow<'slf, CommitHash>>, impl core::error::Error + 'err>;

    fn insert<'slf, 'err: 'slf, 'c>(
        &'slf mut self,
        repo_url: &str,
        git_ref: &str,
        commit_hash: Cow<'c, CommitHash>,
    ) -> Result<(), impl core::error::Error + 'err>;

    fn git_ref_key(repo_url: &str, git_ref: &str) -> String {
        format!("borink-git-ref:{repo_url}:{git_ref}")
    }
}

impl GitRefStore for HashMap<String, CommitHashBuf> {
    fn get<'slf, 'err: 'slf>(
        &'slf self,
        repo_url: &str,
        git_ref: &str,
    ) -> Result<Option<Cow<'slf, CommitHash>>, impl core::error::Error + 'err> {
        let opt = self.get(Self::git_ref_key(repo_url, git_ref).as_str());
        let cow = opt.map(|c| Cow::Borrowed(c.borrow()));
        Ok::<_, Infallible>(cow)
    }

    fn insert<'slf, 'err: 'slf, 'c>(
        &'slf mut self,
        repo_url: &str,
        git_ref: &str,
        commit_hash: Cow<'c, CommitHash>,
    ) -> Result<(), impl core::error::Error + 'err> {
        self.insert(
            Self::git_ref_key(repo_url, git_ref),
            commit_hash.into_owned(),
        );

        Ok::<_, Infallible>(())
    }
}

#[cfg(feature = "kv")]
use borink_kv::{DatabaseRef, KvError, KvMetaValue};

#[cfg(feature = "kv")]
impl<'rf> GitRefStore for DatabaseRef<'rf> {
    fn get<'slf, 'err: 'slf>(
        &'slf self,
        repo_url: &str,
        git_ref: &str,
    ) -> Result<Option<Cow<'slf, CommitHash>>, impl core::error::Error + 'err> {
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

#[cfg(feature = "guarded")]
pub mod guarded {
    use crate::CommitHash;

    pub trait ReadGuard<'guard, T: ?Sized> {
        fn get(&'guard self) -> &'guard T;
    }

    pub trait GitRefGuardedStore {
        type GuardToken<'guard>
        where
            Self: 'guard;
        type ReadGuardType<'guard>: ReadGuard<'guard, CommitHash>
        where
            Self: 'guard;

        // If we don't put the 'err bound on the error, it could maybe reference self, here we require it must
        // at least outlive the reference to self, which should be plenty flexible
        fn get<'store: 'guard, 'err: 'store, 'guard>(
            &'store self,
            repo_url: &str,
            git_ref: &str,
            guard: &'guard Self::GuardToken<'guard>,
        ) -> Result<Option<Self::ReadGuardType<'guard>>, impl core::error::Error + 'err>;

        fn read_guard<'store: 'guard, 'err: 'store, 'guard>(
            &'store self,
        ) -> Result<Self::GuardToken<'guard>, impl core::error::Error + 'err>;

        fn insert<'store, 'err: 'store, 'c>(
            &'store mut self,
            repo_url: &str,
            git_ref: &str,
            commit_hash: std::borrow::Cow<'c, crate::CommitHash>,
        ) -> Result<(), impl core::error::Error + 'err>;

        fn git_ref_key(repo_url: &str, git_ref: &str) -> String {
            format!("borink-git-ref:{repo_url}:{git_ref}")
        }
    }

    #[cfg(feature = "redb")]
    pub mod redb {
        use camino::Utf8Path;
        use redb::{AccessGuard, Database, ReadOnlyTable, TableDefinition};

        use crate::CommitHash;

        use super::{GitRefGuardedStore, ReadGuard};

        type KeysK = &'static str;
        type KeysV = &'static [u8];

        pub struct Store {
            table: TableDefinition<'static, KeysK, KeysV>,
            db: redb::Database,
        }

        const KV_TABLE: TableDefinition<'static, KeysK, KeysV> = TableDefinition::new("kv_table");

        impl Store {
            pub fn open(path: &Utf8Path) -> Result<Self, redb::Error> {
                let db = Database::create(path)?;

                {
                    let tx = db.begin_write()?;
                    // Ensure table is created
                    tx.open_table(KV_TABLE)?;

                    tx.commit()?;
                }

                Ok(Self {
                    table: KV_TABLE,
                    db,
                })
            }
        }

        impl<'guard> ReadGuard<'guard, CommitHash> for AccessGuard<'static, KeysV> {
            fn get(&'guard self) -> &'guard CommitHash {
                let value = self.value();

                let s = std::str::from_utf8(value).unwrap();

                &CommitHash::from_str_unchecked(s)
            }
        }

        impl GitRefGuardedStore for Store {
            type GuardToken<'guard> = ReadOnlyTable<KeysK, KeysV>;
            type ReadGuardType<'guard> = AccessGuard<'static, KeysV>;

            fn get<'store: 'guard, 'err: 'store, 'guard>(
                &'store self,
                repo_url: &str,
                git_ref: &str,
                guard: &'guard Self::GuardToken<'guard>,
            ) -> Result<Option<Self::ReadGuardType<'guard>>, impl core::error::Error + 'err>
            {
                let key = Self::git_ref_key(repo_url, git_ref);

                let opt = guard.get(key.as_str())?;

                Ok::<_, redb::Error>(opt)
            }

            fn read_guard<'store: 'guard, 'err: 'store, 'guard>(
                &'store self,
            ) -> Result<Self::GuardToken<'guard>, impl core::error::Error + 'err> {
                let tx = self.db.begin_read()?;
                let tbl = tx.open_table(self.table)?;

                Ok::<_, redb::Error>(tbl)
            }

            fn insert<'slf, 'err: 'slf, 'c>(
                &'slf mut self,
                repo_url: &str,
                git_ref: &str,
                commit_hash: std::borrow::Cow<'c, crate::CommitHash>,
            ) -> Result<(), impl core::error::Error + 'err> {
                let key = Self::git_ref_key(repo_url, git_ref);

                let tx = self.db.begin_write()?;

                {
                    let mut tbl = tx.open_table(self.table)?;
                    tbl.insert(key.as_str(), commit_hash.as_bytes())?;
                }

                tx.commit()?;

                Ok::<_, redb::Error>(())
            }
        }

        #[cfg(test)]
        mod test {
            use super::*;
            use tempfile::NamedTempFile;

            #[test]
            #[cfg(feature = "redb")]
            fn try_out() {
                use std::borrow::Cow;

                let temp_file = NamedTempFile::new().unwrap();

                let mut db = Store::open(temp_file.path().try_into().unwrap()).unwrap();

                let repo = "some_repo";
                let git_ref = "my_ref";
                let commit = CommitHash::from_str_unchecked("my_hash");

                db.insert(repo, git_ref, Cow::Borrowed(commit)).unwrap();

                let token = db.read_guard().unwrap();

                let g = db.get(repo, git_ref, &token).unwrap().unwrap();

                let c = g.get();

                assert_eq!(commit, c);
            }
        }
    }

    #[cfg(feature = "papaya")]
    pub mod papaya {
        use std::{borrow::Borrow, convert::Infallible};

        use papaya::{HashMap, LocalGuard};

        use crate::{CommitHash, CommitHashBuf};

        use super::{GitRefGuardedStore, ReadGuard};

        pub struct ConcurrentMap {
            inner: HashMap<String, CommitHashBuf>,
        }

        impl ConcurrentMap {
            pub fn new() -> Self {
                Self {
                    inner: papaya::HashMap::new(),
                }
            }
        }

        impl<'guard> ReadGuard<'guard, CommitHash> for &'guard CommitHash {
            fn get(&'guard self) -> &'guard CommitHash {
                &self
            }
        }

        impl GitRefGuardedStore for ConcurrentMap {
            type GuardToken<'guard>
                = LocalGuard<'guard>
            where
                Self: 'guard;
            type ReadGuardType<'guard>
                = &'guard CommitHash
            where
                Self: 'guard;

            fn get<'store: 'guard, 'err: 'store, 'guard>(
                &'store self,
                repo_url: &str,
                git_ref: &str,
                guard: &'guard Self::GuardToken<'guard>,
            ) -> Result<Option<Self::ReadGuardType<'guard>>, impl core::error::Error + 'err>
            {
                let key = Self::git_ref_key(repo_url, git_ref);

                let opt = self.inner.get(key.as_str(), guard).map(|c| c.borrow());

                Ok::<_, Infallible>(opt)
            }

            fn read_guard<'store: 'guard, 'err: 'store, 'guard>(
                &'store self,
            ) -> Result<Self::GuardToken<'guard>, impl core::error::Error + 'err> {
                Ok::<_, Infallible>(self.inner.guard())
            }

            fn insert<'slf, 'err: 'slf, 'c>(
                &'slf mut self,
                repo_url: &str,
                git_ref: &str,
                commit_hash: std::borrow::Cow<'c, crate::CommitHash>,
            ) -> Result<(), impl core::error::Error + 'err> {
                let key = Self::git_ref_key(repo_url, git_ref);

                self.inner.pin().insert(key, commit_hash.into_owned());

                Ok::<_, Infallible>(())
            }
        }

        #[cfg(test)]
        mod test {
            use std::borrow::Cow;

            use super::*;

            #[test]
            fn try_out_papaya() {
                let mut db = ConcurrentMap::new();

                let repo = "some_repo";
                let git_ref = "my_ref";
                let commit = CommitHash::from_str_unchecked("my_hash");

                db.insert(repo, git_ref, Cow::Borrowed(commit)).unwrap();

                let token = db.read_guard().unwrap();

                let g = db.get(repo, git_ref, &token).unwrap().unwrap();

                let c = g.get();

                assert_eq!(commit, c);
            }
        }
    }
}
