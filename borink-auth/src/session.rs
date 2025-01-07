use arrayvec::ArrayVec;
use borink_crypto::{create_symmetric_key, generate_symmetric_decrypt, generate_symmetric_encrypt, AsSymmetricKey, DecryptFailed};
use fixedstr::str256;
use opaque_borink::server::LOGIN_SERVER_STATE_LEN;
use rand::thread_rng;

use std::marker::PhantomData;

use crate::USER_ID_LEN;

pub struct SessionContent<'a> {
    pub user_id: &'a str256,
    pub session_id: u128,
    pub authenticated: u64,
    pub expires: u64
}

// FIXME use the one from the crypto crate
pub const ENCRYPT_ADD: usize = 28;

pub const SESSION_CONTENT_LEN: usize = 16;
pub const SESSION_ASSOC_LEN: usize = USER_ID_LEN + 8 + 8;
pub const SESSION_LEN: usize = SESSION_CONTENT_LEN + ENCRYPT_ADD;

#[cfg(test)]
mod len_test {
    use fixedstr::str256;
    use super::*;

    #[test]
    fn test_lengths() {
        let user_id = str256::new();
        // let session_content = SessionContent {
        //     user_id: &user_id,
        //     session_id: 1,
        //     authenticated: 2,
        //     expires: 3
        // };

        // This should succeed
        serialize_session_associated(&user_id, 2, 3);
    }
}

generate_symmetric_encrypt!(16);
generate_symmetric_decrypt!(16);

pub struct Session {
    encrypted: [u8; SESSION_LEN]
}

pub struct SessionKey(borink_crypto::SymmetricKey);

impl AsSymmetricKey for SessionKey {
    fn as_symmetric_key(&self) -> &borink_crypto::SymmetricKey {
        &self.0
    }
}

impl AsSymmetricKey for &SessionKey {
    fn as_symmetric_key(&self) -> &borink_crypto::SymmetricKey {
        &self.0
    }
}

impl SessionKey {
    pub fn create() -> Self {
        let mut rng = thread_rng();
        let key = create_symmetric_key(&mut rng);

        Self(key)
    }
}

pub trait FixStrIntoArray {
    fn as_array(&self) -> &[u8; 256];
}

impl FixStrIntoArray for str256 {
    fn as_array(&self) -> &[u8; 256] {
        let ptr = self.as_ptr();
        // SAFETY: the pointer returned from the str256 points element with index 1 of a [u8; 256], we simply undo that increment
        unsafe {
            let arr = ptr.offset(-1);
            &*(arr as *const [u8; 256])
        }
    }
}

fn serialize_session_associated(user_id: &str256, authenticated: u64, expires: u64) -> [u8; SESSION_ASSOC_LEN] {
    let mut array_vec: ArrayVec<u8, SESSION_ASSOC_LEN> = ArrayVec::new();
    array_vec.try_extend_from_slice(&authenticated.to_le_bytes()).unwrap();
    array_vec.try_extend_from_slice(&expires.to_le_bytes()).unwrap();
    array_vec.try_extend_from_slice(user_id.as_array()).unwrap();
    
    array_vec.into_inner().unwrap()
}

pub fn encrypt_session(session_id: u128, user_id: &str256, authenticated: u64, expires: u64, key: &SessionKey) -> Session {
    let mut rng = thread_rng();

    let assoc = serialize_session_associated(user_id, authenticated, expires);

    let encrypted = symmetric_encrypt_16(&session_id.to_le_bytes(), &assoc, key, &mut rng);

    Session {
        encrypted
    }
}

pub fn decrypt_session<'a>(session: &Session, user_id: &'a str256, authenticated: u64, expires: u64, key: &SessionKey) -> Result<SessionContent<'a>, DecryptFailed> {
    let assoc = serialize_session_associated(user_id, authenticated, expires);
    
    let decrypted = symmetric_decrypt_16(&session.encrypted, &assoc, &[key])?;

    let session_id = u128::from_le_bytes(decrypted);

    Ok(SessionContent {
        user_id,
        session_id,
        authenticated,
        expires
    })
}