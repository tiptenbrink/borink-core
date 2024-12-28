use std::{borrow::{Borrow, Cow}, convert::Infallible, marker::PhantomData};

use papaya::LocalGuard;
use redb::{AccessGuard, Database, ReadOnlyTable, ReadableTable, TableDefinition};

use crate::{git_ref::{GitRefGuardedStore, ReadGuard}, CommitHash, CommitHashBuf, GitRefStore};

type KeysK = &'static str;
type KeysV = &'static [u8];

pub struct Store {
    table: TableDefinition<'static, KeysK, KeysV>,
    db: redb::Database
}

const KV_TABLE: TableDefinition<'static, KeysK, KeysV> = TableDefinition::new("kv_table");

impl Store {
    fn open() -> Result<Self, redb::Error> {
        let db = Database::create("db.redb")?;

        {
            let tx = db.begin_write()?;
            // Ensure table is created
            tx.open_table(KV_TABLE)?;

            tx.commit()?;
        }
        
        Ok(Self {
            table: KV_TABLE,
            db
        })
    }
    
}

impl<'guard> ReadGuard<'guard, CommitHash> for AccessGuard<'static, &'static [u8]> {
    fn get(&'guard self) -> &'guard CommitHash {
        let value = self.value();

        let s = std::str::from_utf8(value).unwrap();
        
        &CommitHash::from_str_unchecked(s)
    }
}

impl GitRefGuardedStore for Store {
    type GuardToken<'guard> = ReadOnlyTable<&'static str, &'static [u8]>;
    type ReadGuardType<'guard> = AccessGuard<'static, &'static [u8]>;

    fn get<'store: 'guard, 'err: 'store, 'guard>(&'store self, repo_url: &str, git_ref: &str, guard: &'guard Self::GuardToken<'guard>) -> Result<Option<Self::ReadGuardType<'guard>>, impl core::error::Error + 'err> {
        let key = Self::git_ref_key(repo_url, git_ref);

        let opt = guard.get(key.as_str())?;

        Ok::<_, redb::Error>(opt)
    }

    fn read_guard<'store: 'guard, 'err: 'store, 'guard>(&'store self) -> Result<Self::GuardToken<'guard>, impl core::error::Error + 'err> {
        let tx = self.db.begin_read()?;
        let tbl = tx.open_table(self.table)?;

        Ok::<_, redb::Error>(tbl)
    }

    fn insert<'slf, 'err: 'slf, 'c>(&'slf mut self, repo_url: &str, git_ref: &str, commit_hash: std::borrow::Cow<'c, crate::CommitHash>) -> Result<(), impl core::error::Error + 'err> {
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

struct ConcurrentMap {
    inner: papaya::HashMap<String, CommitHashBuf>
}

impl ConcurrentMap {
    pub fn new() -> Self {
        Self {
            inner: papaya::HashMap::new()
        }
    }
}

impl<'guard> ReadGuard<'guard, CommitHash> for &'guard CommitHash {
    fn get(&'guard self) -> &'guard CommitHash {
        &self
    }
}

impl GitRefGuardedStore for ConcurrentMap {
    type GuardToken<'guard> = LocalGuard<'guard> where Self: 'guard;
    type ReadGuardType<'guard> = &'guard CommitHash where Self: 'guard;

    fn get<'store: 'guard, 'err: 'store, 'guard>(&'store self, repo_url: &str, git_ref: &str, guard: &'guard Self::GuardToken<'guard>) -> Result<Option<Self::ReadGuardType<'guard>>, impl core::error::Error + 'err> {
        let key = Self::git_ref_key(repo_url, git_ref);
        
        let opt = self.inner.get(key.as_str(), guard).map(|c| c.borrow());

        Ok::<_, Infallible>(opt)
    }

    fn read_guard<'store: 'guard, 'err: 'store, 'guard>(&'store self) -> Result<Self::GuardToken<'guard>, impl core::error::Error + 'err> {
        Ok::<_, Infallible>(self.inner.guard())
    }

    fn insert<'slf, 'err: 'slf, 'c>(&'slf mut self, repo_url: &str, git_ref: &str, commit_hash: std::borrow::Cow<'c, crate::CommitHash>) -> Result<(), impl core::error::Error + 'err> {
        let key = Self::git_ref_key(repo_url, git_ref);

        self.inner.pin().insert(key, commit_hash.into_owned());

        Ok::<_, Infallible>(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn try_out() {
        let mut db = Store::open().unwrap();
    
        let repo = "some_repo";
        let git_ref = "my_ref";
        let commit = CommitHash::from_str_unchecked("my_hash");
    
        db.insert(repo, git_ref, Cow::Borrowed(commit)).unwrap();

        println!("inserted!");
    
        let token = db.read_guard().unwrap();
    
        let g = db.get(repo, git_ref, &token).unwrap().unwrap();
    
        let c = g.get();
    
        assert_eq!(commit, c);
    }

    #[test]
    fn try_out_papaya() {
        let mut db = ConcurrentMap::new();
    
        let repo = "some_repo";
        let git_ref = "my_ref";
        let commit = CommitHash::from_str_unchecked("my_hash");
    
        db.insert(repo, git_ref, Cow::Borrowed(commit)).unwrap();

        println!("inserted!");
    
        let token = db.read_guard().unwrap();
    
        let g = db.get(repo, git_ref, &token).unwrap().unwrap();
    
        let c = g.get();
    
        assert_eq!(commit, c);
    }
}

