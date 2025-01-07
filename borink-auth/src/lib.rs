#![allow(unused)]

mod compactset;
mod ephemeral;
mod login;
mod session;
use std::sync::atomic::{self, AtomicU64};

use compactset::{AtomicBitSet, AtomicSmallBitSet, CompactSet};
use fixedstr::str256;
use opaque_borink::server::PasswordFile;
use papaya::HashMap;

struct Database {}

struct UserState {
    counter: AtomicU64,
    seen: AtomicSmallBitSet,
}

impl UserState {
    fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
            seen: AtomicSmallBitSet::new(),
        }
    }

    fn next(&self) -> u64 {
        self.counter.fetch_add(1, atomic::Ordering::Relaxed)
    }

    fn seen(&self, num: u64) -> bool {
        CompactSet::exists(&self.seen, num)
    }

    fn reset(&self) {
        self.counter.store(0, atomic::Ordering::Relaxed);
        self.seen.reset();
    }
}

pub const USER_ID_LEN: usize = 256;

pub struct User {
    user_id: str256,
    state: UserState,
    password_file: PasswordFile,
    // For use with other things
    // FIXME make optional serialized version of the password file?
    metadata: [u8; 172],
}

// This will be to support webauthn/passkeys in the future
struct UserCredentials {
    user_id: str256,
    credentials: Vec<u8>,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

impl core::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first_zero = 1;
        let password_file = self.password_file.serialize();
        for (i, b) in password_file.iter().enumerate().rev() {
            if *b != 0 {
                first_zero = i + 1;
                break;
            }
        }

        let pw_format = if first_zero <= 16 {
            format!("{}", to_hex(&password_file[0..first_zero]))
        } else {
            let end_start = (first_zero - 16).max(16);
            format!(
                "{}..{}",
                to_hex(&password_file[0..16]),
                to_hex(&password_file[end_start..first_zero])
            )
        };
        write!(f, "User{{id={};pw_file={}}}", self.user_id, pw_format)
    }
}

const BLOCK_SIZE: usize = 16;

// Searching through a block and matching every user_id takes about 1-2 us.
pub struct UserBlock {
    users: [User; BLOCK_SIZE],
}

#[cfg(test)]
pub mod test_util {
    use opaque_borink::encoded::decode_string;
    use rand::thread_rng;
    use rand::{distributions::Alphanumeric, Rng};

    use super::*;

    use opaque_borink::client::{
        client_register_finish, client_register_start, ClientStateRegistration,
    };
    use opaque_borink::server::{
        server_register_finish, server_register_start, PasswordFile, ServerSetupView,
    };

    pub fn gen_password_file_with_setup_and_pw(
        setup: &mut ServerSetupView,
        user_id: &[u8],
        password: &[u8],
    ) -> PasswordFile {
        let mut client_state = ClientStateRegistration::setup();

        let client_start = client_register_start(&mut client_state, password).unwrap();

        let server_start = server_register_start(setup, &client_start.response, user_id).unwrap();

        let client_finish =
            client_register_finish(&mut client_state, password, &server_start.response).unwrap();

        let server_finish = server_register_finish(&client_finish.response).unwrap();

        server_finish
    }

    pub fn gen_user_name() -> str256 {
        let mut rng = thread_rng();
        let length = rng.gen_range(1..=16);
        let s: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect();

        str256::make(&s)
    }

    pub fn gen_user() -> User {
        let mut rng = rand::thread_rng();
        let length = rng.gen_range(1..=16);
        let s: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect();

        let dummy_pw_file = "LJ0rg3mSZ-x1tDbobI0xvroBjAPQ5fnAgrnEmxc67giA0XDjR8pJaOuNGlWtRku5Hk57yBlL6YrjBUQJ--7OMhPZra40WvmWSu7yT8s-CBAsE0jobWK-9qXk3xDv7TlK-g_TF3JzR3s8MntBWjIuN5Ii7Le93coLGLvm7xjQtuYHbszz3HBv-gBu_xlj7YitpgyQzYpcJGslbezqxEvZz4Jz0R64np94JBDibI7syTw13ZJ74tbjWiJbvwvKb5a-";
        let dummy_pw_file = decode_string(dummy_pw_file).unwrap();
        let dummy_pw_file = PasswordFile::deserialize(&dummy_pw_file).unwrap();
        let meta_buf = [0u8; 172];

        User {
            user_id: str256::make(&s),
            password_file: dummy_pw_file,
            state: UserState::new(),
            metadata: meta_buf,
        }
    }

    pub fn gen_block() -> UserBlock {
        let mut users = Vec::with_capacity(BLOCK_SIZE);

        for _ in 0..BLOCK_SIZE {
            users.push(gen_user());
        }

        UserBlock {
            users: users.try_into().unwrap(),
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Instant;

    use opaque_borink::{encoded::decode_string, server::PASSWORD_FILE_LEN};
    use rand::{distributions::Alphanumeric, Rng, RngCore};
    use test_util::{gen_block, gen_user};

    use super::*;

    // cargo test --package borink-auth --lib --release --all-features -- test::search_block --exact --show-output
    #[test]
    fn search_block() {
        let iters = 1;
        let mut found_users = Vec::new();

        let mut blocks = Vec::new();

        for _ in 0..iters {
            let mut block = gen_block();
            let genned_user = gen_user();
            let name = genned_user.user_id.clone();
            block.users[BLOCK_SIZE - 1] = genned_user;
            blocks.push((block, name));
        }

        let time = Instant::now();
        for (block, name) in blocks {
            for u in block.users {
                if name == u.user_id {
                    found_users.push(u.user_id.clone());
                    break;
                }
            }
        }
        let elapsed = time.elapsed().as_nanos();
        let iter_per_elap = (iters as f64) / (elapsed as f64) * 1_000_000_000f64;
        println!(
            "{} searches/s. {} us/search",
            iter_per_elap,
            1_000_000f64 / iter_per_elap
        );
        println!("{:?}", found_users[0])
    }
}
