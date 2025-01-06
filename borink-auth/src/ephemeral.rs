
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
    eph: Ephemeral<LOGIN_SERVER_STATE_LEN>
}