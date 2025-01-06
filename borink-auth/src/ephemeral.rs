
use borink_crypto::{generate_symmetric_decrypt, generate_symmetric_encrypt};
// trait ByteSerial {
//     fn serialize(&self)
// }
use opaque_borink::server::LOGIN_SERVER_STATE_LEN;

use std::marker::PhantomData;

struct Ephemeral<const N: usize, T> {
    phantom: PhantomData<T>,
    encrypted: [u8; N]
}

struct EphemeralLogin {
    eph: Ephemeral<LOGIN_SERVER_STATE_LEN, u8>
}

generate_symmetric_encrypt!(192);
generate_symmetric_decrypt!(192);

fn encrypt_login() {
    let encrypted = symmetric_encrypt_192(data, key, rng);
}