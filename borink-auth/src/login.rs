use std::borrow::Cow;

use crate::{ephemeral::{decrypt_login, encrypt_login, EphemeralKey, LoginEphemeral}, User};
use crate::compactset::CompactSet;
use borink_crypto::DecryptFailed;
use opaque_borink::{client::LOGIN_FINISH_MESSAGE_LEN, server::{server_login_finish, server_login_start, ServerLoginStartResult, ServerSetup, LOGIN_SERVER_MESSAGE_LEN, SHARED_SECRET_LEN}};
use thiserror::Error as ThisError;
#[derive(Debug, ThisError)]
#[error("Login failed.")]
struct LoginError;

impl From<opaque_borink::Error> for LoginError {
    fn from(value: opaque_borink::Error) -> Self {
        Self
    }
}

impl From<DecryptFailed> for LoginError {
    fn from(value: DecryptFailed) -> Self {
        Self
    }
}

fn login_start<'a>(setup: &ServerSetup, user: &'a User, login_start_request: &[u8], key: &EphemeralKey) -> Result<LoginStartMessage<'a>, LoginError> {
    // FIXME once new version is uploaded but view as argument
    let mut setup = setup.view();

    let result = server_login_start(&mut setup, &user.password_file, login_start_request, &user.user_id)?;

    let eph_id = user.state.next();

    Ok(LoginStartMessage::create(result, &user.user_id, eph_id, key))
}

struct LoginStartMessage<'a> {
    message: [u8; LOGIN_SERVER_MESSAGE_LEN],
    eph: LoginEphemeral,
    user_id: &'a str,
    eph_id: u64
}

impl<'a> LoginStartMessage<'a> {
    fn create(result: ServerLoginStartResult, user_id: &'a str, eph_id: u64, key: &EphemeralKey) -> Self {
        let assoc = LoginStartAssociated { user_id, eph_id };
        let eph = encrypt_login(&result.state, &assoc.serialize_associated(), key);

        LoginStartMessage {
            message: result.response,
            eph,
            user_id,
            eph_id
        }
    }
}

struct LoginFinishRequestView<'a> {
    message: &'a [u8; LOGIN_FINISH_MESSAGE_LEN],
    eph: &'a LoginEphemeral,
    user_id: &'a str,
    eph_id: u64,
    shared_secret: &'a [u8; SHARED_SECRET_LEN]
} 

// trait AssociatedView {
//     fn serialize<'a>(&'a self) -> Cow<'a, [u8]>;
// }

// trait AssociatedData {
//     type AssociatedView<'a>: AssociatedView where Self: 'a;

//     fn associated_view<'a>(&'a self) -> Self::AssociatedView<'a>;
// }

struct LoginStartAssociated<'a> {
    pub user_id: &'a str,
    pub eph_id: u64
}

impl<'a> LoginStartAssociated<'a> {
    fn serialize_associated(&self) -> Cow<'a, [u8]> {
        let eph_id_bytes = self.eph_id.to_le_bytes();
        let mut vec = Vec::with_capacity(self.user_id.len()+eph_id_bytes.len());
        vec.extend_from_slice(self.user_id.as_bytes());
        vec.extend_from_slice(&eph_id_bytes);

        Cow::Owned(vec)
    }
}

// impl<'a> AssociatedData for LoginStartMessage<'a> {
//     type AssociatedView<'b> = LoginStartAssociated<'b> where Self: 'b;

    
    
//     fn associated_view<'b>(&'b self) -> Self::AssociatedView<'b> {
//         LoginStartAssociated {
//             user_id: &self.user_id,
//             eph_id: self.eph_id
//         }
//     }
// }

fn login_session(login_finish_request: LoginFinishRequestView, user: &User, keys: &[EphemeralKey]) -> Result<(), LoginError> {
    // We want the associated data still in a serialized state here
    let assoc = LoginStartAssociated { user_id: login_finish_request.user_id, eph_id: login_finish_request.eph_id };
    let decrypted = decrypt_login(login_finish_request.eph, &assoc.serialize_associated(), keys)?;

    // Apparently this ephemeral has already been used!
    if user.state.seen(assoc.eph_id) {
        return Err(LoginError)
    }
    
    let result = server_login_finish(login_finish_request.message.as_slice(), &decrypted)?;

    if &result.shared_secret != login_finish_request.shared_secret {
        return Err(LoginError)
    }
    

    todo!()
}