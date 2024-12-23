use camino::Utf8Path;
use rusqlite::{Connection, Statement};
use std::{cell::RefCell, result};
use thiserror::Error as ThisError;

use borink_error::{ContextSource, StringContext};

pub type Result<T, E = KvError> = result::Result<T, E>;

fn set_options(conn: &Connection) -> Result<()> {
    Ok(conn
        .execute_batch(
            "PRAGMA journal_mode = WAL;
        PRAGMA temp_store = MEMORY;
        PRAGMA synchronous = NORMAL;
        PRAGMA cache_size = -64000;",
        )
        .to_kv_err("failed to set storage engine options")?)
}

fn create_kv_table(conn: &Connection) -> Result<()> {
    Ok(conn
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS key_value (
            key BLOB PRIMARY KEY,
            meta BLOB,
            value BLOB
        ) STRICT;
        CREATE INDEX IF NOT EXISTS meta_index ON key_value (meta);",
        )
        .to_kv_err("failed to create kv table")?)
}

pub fn recreate_kv_table(conn: &Connection) -> Result<()> {
    conn.execute("DROP TABLE IF EXISTS key_value", [])
        .to_kv_err("failed to drop kv table")?;
    create_kv_table(conn)
}

struct KvOperations<'a> {
    insert_stmt: Statement<'a>,
    update_if_meta_stmt: Statement<'a>,
    get_meta_stmt: Statement<'a>,
    get_stmt: Statement<'a>,
    metas_stmt: Statement<'a>,
}

pub fn create_conn(db_path: &Utf8Path) -> Result<Connection> {
    let conn = Connection::open(db_path).to_kv_err(format!(
        "error opening connection to db at path {}",
        db_path
    ))?;
    set_options(&conn)?;
    create_kv_table(&conn)?;

    Ok(conn)
}

/// The DatabaseRef does not require mutable access in order to execute, but uses a RefCell!
/// TODO: investigate the consequences of this further
pub struct DatabaseRef<'a> {
    connection: &'a Connection,
    ops: RefCell<KvOperations<'a>>,
}

impl<'a> DatabaseRef<'a> {
    fn prepare_from_conn(conn: &'a Connection) -> Result<Self> {
        let ops = RefCell::new(KvOperations::new(conn)?);

        Ok(Self {
            connection: conn,
            ops,
        })
    }

    /// This creates a new sets of prepared statements using the same connection.
    pub fn prepare_new(&self) -> Result<Self> {
        Self::prepare_from_conn(self.connection)
    }

    pub fn insert(&self, key: &[u8], meta: &[u8], value: &[u8]) -> Result<()> {
        let mut ops = self.ops.borrow_mut();
        db::insert(&mut ops, key, meta, value)
    }

    pub fn update_if_meta(
        &self,
        key: &[u8],
        new_meta: &[u8],
        value: &[u8],
        if_meta: &[u8],
    ) -> Result<bool> {
        let mut ops = self.ops.borrow_mut();
        db::update_if_meta(&mut ops, key, new_meta, value, if_meta)
    }

    pub fn get_meta(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut ops = self.ops.borrow_mut();
        db::get_meta(&mut ops, key)
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<KvMetaValue>> {
        let mut ops = self.ops.borrow_mut();
        db::get(&mut ops, key)
    }

    pub fn exists(&self, key: &[u8]) -> Result<bool> {
        let mut ops = self.ops.borrow_mut();
        db::exists(&mut ops, key)
    }

    pub fn metas(&self, range_start: &[u8], range_end_exclusive: &[u8]) -> Result<Vec<KvMetaKey>> {
        let mut ops = self.ops.borrow_mut();
        db::metas(&mut ops, range_start, range_end_exclusive)
    }
}

/// We encapsulate in a module so that the fields of Database are not used
mod db {
    use crate::{DatabaseRef, WrapSqliteError};

    use super::{create_conn, KvError, KvMetaKey, KvMetaValue, KvOperations, Result};
    use camino::Utf8Path;
    use ouroboros::self_referencing;
    use rusqlite::{params, Connection, OptionalExtension};

    /// We use a self_referencing struct so that the initialization can be done in two steps. We encapsulate it so that the namespace does not get polluted
    /// by the various builders and generated methods.
    #[self_referencing]
    struct InternalDatabase {
        conn: Connection,
        // Note that without the 'not_covariant' you get a cryptic error
        #[borrows(conn)]
        #[not_covariant]
        ops: KvOperations<'this>,
    }

    pub struct Database(InternalDatabase);

    impl Database {
        pub fn open(db_path: &Utf8Path) -> Result<Self> {
            let connection = create_conn(db_path)?;

            let internal_db = InternalDatabaseTryBuilder {
                conn: connection,
                ops_builder: |conn: &Connection| {
                    let ops = KvOperations::new(conn)?;

                    Ok::<KvOperations, KvError>(ops)
                },
            }
            .try_build()?;

            Ok(Self(internal_db))
        }

        /// Create a new DatabaseRef from the same underlying connection that has its own set of
        /// prepared statements. A DatabaseRef has the additional property that its query functions
        /// don't require mutable access. However, each DatabaseRef should only exist once.
        pub fn prepare_new_ref<'conn>(&'conn self) -> Result<DatabaseRef<'conn>> {
            DatabaseRef::prepare_from_conn(self.conn())
        }

        pub fn conn(&self) -> &Connection {
            self.0.borrow_conn()
        }

        pub fn insert(&mut self, key: &[u8], meta: &[u8], value: &[u8]) -> Result<()> {
            self.0.with_ops_mut(|ops| insert(ops, key, meta, value))
        }

        pub fn update_if_meta(
            &mut self,
            key: &[u8],
            new_meta: &[u8],
            value: &[u8],
            if_meta: &[u8],
        ) -> Result<bool> {
            self.0
                .with_ops_mut(|ops| update_if_meta(ops, key, new_meta, value, if_meta))
        }

        pub fn get_meta(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            self.0.with_ops_mut(|ops| get_meta(ops, key))
        }

        pub fn get(&mut self, key: &[u8]) -> Result<Option<KvMetaValue>> {
            self.0.with_ops_mut(|ops| get(ops, key))
        }

        pub fn exists(&mut self, key: &[u8]) -> Result<bool> {
            self.0.with_ops_mut(|ops| exists(ops, key))
        }

        pub fn metas(
            &mut self,
            range_start: &[u8],
            range_end_exclusive: &[u8],
        ) -> Result<Vec<KvMetaKey>> {
            self.0
                .with_ops_mut(|ops| metas(ops, range_start, range_end_exclusive))
        }
    }

    pub fn insert(ops: &mut KvOperations, key: &[u8], meta: &[u8], value: &[u8]) -> Result<()> {
        ops.insert_stmt
            .execute(params![key, meta, value])
            .to_kv_err("error during insert")?;
        Ok(())
    }

    pub fn update_if_meta(
        ops: &mut KvOperations,
        key: &[u8],
        new_meta: &[u8],
        value: &[u8],
        if_meta: &[u8],
    ) -> Result<bool> {
        let changes = ops
            .update_if_meta_stmt
            .execute(params![new_meta, value, key, if_meta])
            .to_kv_err("error during update_if_meta")?;
        Ok(changes == 1)
    }

    pub fn get_meta(ops: &mut KvOperations, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(ops
            .get_meta_stmt
            .query_row(params![key], |row| row.get::<_, Vec<u8>>(0))
            .optional()
            .to_kv_err("error during get_meta")?)
    }

    pub fn get(ops: &mut KvOperations, key: &[u8]) -> Result<Option<KvMetaValue>> {
        Ok(ops
            .get_stmt
            .query_row(params![key], |row| {
                Ok(KvMetaValue {
                    value: row.get(0)?,
                    metadata: row.get(1)?,
                })
            })
            .optional()
            .to_kv_err("error during get")?)
    }

    pub fn exists(ops: &mut KvOperations, key: &[u8]) -> Result<bool> {
        Ok(get_meta(ops, key)?.is_some())
    }

    pub fn metas(
        ops: &mut KvOperations,
        range_start: &[u8],
        range_end_exclusive: &[u8],
    ) -> Result<Vec<KvMetaKey>> {
        let mut stmt = ops
            .metas_stmt
            .query(params![range_start, range_end_exclusive])
            .to_kv_err("error during metas")?;
        let mut results = Vec::new();

        while let Some(row) = stmt.next().to_kv_err("error getting next row from metas")? {
            // This order depends on the order in the query
            let metadata: Vec<u8> = row
                .get(0)
                .to_kv_err("error getting first column from row during metas")?;
            let key: Vec<u8> = row
                .get(1)
                .to_kv_err("error getting second column from row during metas")?;
            results.push(KvMetaKey { metadata, key });
        }

        Ok(results)
    }
}

pub use db::Database;

pub struct KvMetaKey {
    pub metadata: Vec<u8>,
    pub key: Vec<u8>,
}

pub struct KvMetaValue {
    pub metadata: Vec<u8>,
    pub value: Vec<u8>,
}

impl<'a> KvOperations<'a> {
    pub fn new(conn: &'a Connection) -> Result<Self> {
        let insert_stmt = conn
            .prepare("INSERT OR REPLACE INTO key_value (key, meta, value) VALUES (?, ?, ?);")
            .to_kv_err("error preparing insert statement")?;
        let update_if_meta_stmt = conn
            .prepare("UPDATE key_value SET meta = ?, value = ? WHERE key = ? AND meta = ?;")
            .to_kv_err("error preparing update_if_meta statement")?;
        let get_meta_stmt = conn
            .prepare("SELECT meta FROM key_value WHERE key = ?;")
            .to_kv_err("error preparing get_meta statement")?;
        let get_stmt = conn
            .prepare("SELECT value, meta FROM key_value WHERE key = ?;")
            .to_kv_err("error preparing get statement")?;
        let metas_stmt = conn
            .prepare("SELECT meta, key FROM key_value WHERE meta >= ? AND meta < ?;")
            .to_kv_err("error preparing metas statement")?;

        Ok(Self {
            insert_stmt,
            update_if_meta_stmt,
            get_meta_stmt,
            get_stmt,
            metas_stmt,
        })
    }
}

/// In general, value metadata is expected to consist of some 3 byte prefix, up to 64 kilobytes of bytes that can be used to search on, and general metadata.
/// This function allows building metadata of this form.
pub fn join_prefix_with_meta(
    prefix: &[u8; 3],
    search_bytes: &[u8],
    meta_bytes: Option<&[u8]>,
) -> Vec<u8> {
    if search_bytes.len() > u16::MAX as usize {
        panic!("Search bytes length cannot exceed the max size of a u16 (~64 kB)!")
    }
    let mut final_bytes = Vec::with_capacity(
        prefix.len() + 2 + search_bytes.len() + meta_bytes.map_or(0, |mb| mb.len()),
    );
    final_bytes.extend_from_slice(prefix);
    final_bytes.extend_from_slice(&(search_bytes.len() as u16).to_le_bytes());
    final_bytes.extend_from_slice(search_bytes);
    if let Some(meta_bytes) = meta_bytes {
        final_bytes.extend_from_slice(meta_bytes);
    }
    final_bytes
}

pub fn prefix_range(start: &[u8]) -> Vec<u8> {
    let mut result = start.to_vec();
    for i in (0..result.len()).rev() {
        if result[i] < 255 {
            result[i] += 1; // Return as soon as we successfully increment without overflow
            return result;
        } else {
            result[i] = 0; // Handle overflow for the current byte
        }
    }
    // If we overflowed the entire array, create a new array with an additional byte
    let mut extended_result = Vec::with_capacity(result.len() + 1);
    extended_result[0] = 1;
    extended_result.extend_from_slice(&result);
    extended_result
}

pub struct KvMetadata {
    pub prefix: [u8; 3],

    pub search_bytes: Vec<u8>,
    pub meta_bytes: Vec<u8>,
}

pub fn read_meta(meta: &[u8]) -> Result<KvMetadata> {
    if meta.len() < 5 {
        return Err(KvError::InvalidMetadata(
            "Meta should be at least 5 bytes due to prefix and search byte length!".into(),
        ));
    }
    let prefix: [u8; 3] = meta[..3].try_into().unwrap();
    let search_length = u16::from_le_bytes([meta[3], meta[4]]) as usize;
    if meta.len() < 5 + search_length {
        return Err(KvError::InvalidMetadata(
            "Metadata is not at least length given in search length!".into(),
        ));
    }
    let search_bytes = meta[5..5 + search_length].to_vec();
    let meta_bytes = meta[5 + search_length..].to_vec();
    Ok(KvMetadata {
        prefix,
        search_bytes,
        meta_bytes,
    })
}

pub trait WrapSqliteError<T> {
    fn to_kv_err<S: Into<String>>(self, message: S) -> Result<T, KvError>;
}

impl<T> WrapSqliteError<T> for Result<T, rusqlite::Error> {
    fn to_kv_err<S: Into<String>>(self, message: S) -> Result<T, KvError> {
        self.map_err(|e| KvError::SqliteError(OpaqueDbError(ContextSource::new(message, e))))
    }
}

#[derive(ThisError, Debug)]
#[error("{0}")]
/// Opaque error to hide the implementation of the storage engine from the public API.
/// Changes in the display implementation of this error are not considered part of the public API.
pub struct OpaqueDbError(ContextSource<rusqlite::Error>);

#[derive(ThisError, Debug)]
pub enum KvError {
    #[error("kv error from sqlite:\n{0}")]
    SqliteError(#[from] OpaqueDbError),
    #[error("kv error due to invalid metadata:\n{0}")]
    InvalidMetadata(StringContext),
}
