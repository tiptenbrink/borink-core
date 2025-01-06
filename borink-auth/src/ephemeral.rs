
use borink_crypto::{generate_symmetric_decrypt, generate_symmetric_encrypt, AsSymmetricKey, DecryptFailed};
use opaque_borink::server::LOGIN_SERVER_STATE_LEN;
use rand::thread_rng;

use std::marker::PhantomData;


pub trait EphemeralType<const N: usize> {
    fn name() -> &'static str;
}

pub struct Login;

impl EphemeralType<{ ENCRYPT_ADD + LOGIN_SERVER_STATE_LEN }> for Login {
    fn name() -> &'static str {
        "login_finish"
    }
}

pub struct Ephemeral<const N: usize, T: EphemeralType<N>> {
    phantom: PhantomData<T>,
    encrypted: [u8; N],

}

impl<const N: usize, T: EphemeralType<N>> Ephemeral<N, T> {
    fn new(encrypted: [u8; N]) -> Self {
        Self { phantom: PhantomData, encrypted }
    }
}

pub type LoginEphemeral = Ephemeral<{ LOGIN_SERVER_STATE_LEN + 28 }, Login>;

generate_symmetric_encrypt!(192);
generate_symmetric_decrypt!(192);

pub struct EphemeralKey(borink_crypto::SymmetricKey);

impl AsSymmetricKey for EphemeralKey {
    fn as_symmetric_key(&self) -> &borink_crypto::SymmetricKey {
        &self.0
    }
}

pub fn encrypt_login(login_server_state: &[u8; LOGIN_SERVER_STATE_LEN], login_associated: &[u8], key: &EphemeralKey) -> LoginEphemeral {
    let mut rng = thread_rng();

    let encrypted = symmetric_encrypt_192(login_server_state, login_associated, key, &mut rng);

    Ephemeral::new(encrypted)
}

pub const ENCRYPT_ADD: usize = 28;

pub fn decrypt_login(eph: &LoginEphemeral, login_associated: &[u8], keys: &[EphemeralKey]) -> Result<[u8; LOGIN_SERVER_STATE_LEN], DecryptFailed> {
    let decrypted = symmetric_decrypt_192(&eph.encrypted, login_associated, keys)?;

    Ok(decrypted)
}

// trait Verified<const N: usize> {
//     type Eph: EphemeralType<N>;


// }