#![allow(unused)]

mod ephemeral;
mod compactset;
mod login;
use compactset::{AtomicSmallBitSet, CompactSet, AtomicBitSet};
use fixedstr::zstr;
use opaque_borink::server::{PasswordFile};
use papaya::HashMap;

struct Database {

}

struct User {
    user_id: zstr<256>,
    counter: AtomicSmallBitSet,
    password_file: PasswordFile,
    // For use with other things
    metadata: [u8; 184]
}

// This will be to support webauthn/passkeys in the future
struct UserCredentials {
    user_id: zstr<256>,
    credentials: Vec<u8>
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|byte| format!("{:02x}", byte)) 
        .collect()
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
            let end_start = (first_zero-16).max(16);
            format!("{}..{}", to_hex(&password_file[0..16]), to_hex(&password_file[end_start..first_zero]))
        };
        write!(f, "User{{id={};pw_file={}}}", self.user_id, pw_format)
    }
}

const BLOCK_SIZE: usize = 16;

// Searching through a block and matching every user_id takes about 1-2 us.
struct UserBlock {
    users: [User; BLOCK_SIZE]
}

mod test {
    use std::time::Instant;

    use opaque_borink::{encoded::decode_string, server::PASSWORD_FILE_LEN};
    use rand::{distributions::Alphanumeric, Rng, RngCore};

    use super::*;

    fn gen_user() -> User {
        let mut rng = rand::thread_rng();
        let length = rng.gen_range(1..=16);
        let s: String = rand::thread_rng().sample_iter(&Alphanumeric).take(length).map(char::from).collect();

        let dummy_pw_file = "LJ0rg3mSZ-x1tDbobI0xvroBjAPQ5fnAgrnEmxc67giA0XDjR8pJaOuNGlWtRku5Hk57yBlL6YrjBUQJ--7OMhPZra40WvmWSu7yT8s-CBAsE0jobWK-9qXk3xDv7TlK-g_TF3JzR3s8MntBWjIuN5Ii7Le93coLGLvm7xjQtuYHbszz3HBv-gBu_xlj7YitpgyQzYpcJGslbezqxEvZz4Jz0R64np94JBDibI7syTw13ZJ74tbjWiJbvwvKb5a-";
        let dummy_pw_file = decode_string(dummy_pw_file).unwrap();
        let dummy_pw_file = PasswordFile::deserialize(&dummy_pw_file).unwrap();
        let meta_buf = [0u8; 184];

        User {
            user_id: zstr::make(&s),
            password_file: dummy_pw_file,
            counter: AtomicSmallBitSet::new(),
            metadata: meta_buf
        }
    }

    fn gen_block() -> UserBlock {
        let mut users = Vec::with_capacity(BLOCK_SIZE);

        for _ in 0..BLOCK_SIZE {
            users.push(gen_user());
        }

        UserBlock { users: users.try_into().unwrap() }
    }

    // cargo test --package borink-auth --lib --release --all-features -- test::search_block --exact --show-output
    #[test]
    fn search_block() {
        
        
        let iters = 50000;
        let mut found_users = Vec::new();

        let mut blocks = Vec::new();

        for _ in 0..iters {
            let mut block = gen_block();
            let genned_user = gen_user();
            let name = genned_user.user_id.clone();
            block.users[BLOCK_SIZE-1] = genned_user;
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
        let iter_per_elap = (iters as f64)/(elapsed as f64)*1_000_000_000f64;
        println!("{} searches/s. {} us/search", iter_per_elap, 1_000_000f64/iter_per_elap);
        println!("{:?}", found_users[6])
        
    }
}