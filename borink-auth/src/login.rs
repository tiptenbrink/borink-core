use std::borrow::Cow;

use crate::compactset::CompactSet;
use crate::{
    ephemeral::{decrypt_login, encrypt_login, EphemeralKey, LoginEphemeral},
    session::{encrypt_session, Session, SessionKey},
    User,
};
use borink_crypto::DecryptFailed;
use opaque_borink::{
    client::LOGIN_FINISH_MESSAGE_LEN,
    server::{
        server_login_finish, server_login_start, PasswordFile, ServerLoginStartResult, ServerSetup,
        ServerSetupView, LOGIN_SERVER_MESSAGE_LEN, SHARED_SECRET_LEN,
    },
};
use rand::{thread_rng, Rng};
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

fn login_start<'a>(
    setup: &mut ServerSetupView,
    user: &'a User,
    login_start_request: &[u8],
    key: &EphemeralKey,
) -> Result<LoginStartMessage<'a>, LoginError> {
    let result = server_login_start(
        setup,
        &user.password_file,
        login_start_request,
        &user.user_id,
    )?;

    let eph_id = user.state.next();

    Ok(LoginStartMessage::create(
        result,
        &user.user_id,
        &user.password_file.serialize(),
        eph_id,
        key,
    ))
}

struct LoginStartMessage<'a> {
    message: [u8; LOGIN_SERVER_MESSAGE_LEN],
    eph: LoginEphemeral,
    user_id: &'a str,
    eph_id: u64,
}

impl<'a> LoginStartMessage<'a> {
    fn create(
        result: ServerLoginStartResult,
        user_id: &'a str,
        password_file: &[u8],
        eph_id: u64,
        key: &EphemeralKey,
    ) -> Self {
        let assoc = LoginStartAssociated {
            user_id,
            eph_id,
            password_file,
        };
        let eph = encrypt_login(&result.state, &assoc.serialize_associated(), key);

        LoginStartMessage {
            message: result.response,
            eph,
            user_id,
            eph_id,
        }
    }
}

struct LoginFinishRequestView<'a> {
    message: &'a [u8; LOGIN_FINISH_MESSAGE_LEN],
    eph: &'a LoginEphemeral,
    user_id: &'a str,
    eph_id: u64,
    shared_secret: &'a [u8; SHARED_SECRET_LEN],
}

// trait AssociatedView {
//     fn serialize<'a>(&'a self) -> Cow<'a, [u8]>;
// }

// trait AssociatedData {
//     fn associated_view(&'a self) -> Self::AssociatedView<'a>;
// }

struct LoginStartAssociated<'a> {
    pub password_file: &'a [u8],
    pub user_id: &'a str,
    pub eph_id: u64,
}

impl<'a> LoginStartAssociated<'a> {
    fn serialize_associated(&self) -> Cow<'a, [u8]> {
        let eph_id_bytes = self.eph_id.to_le_bytes();
        let mut vec =
            Vec::with_capacity(self.password_file.len() + self.user_id.len() + eph_id_bytes.len());
        vec.extend_from_slice(&self.password_file);
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

// Might make this application-specific
// 30 days
pub const SESSION_EXPIRE: u64 = const { 60 * 60 * 24 * 30 };

pub struct SessionMessage {
    session: Session,
    authenticated: u64,
    expires: u64,
}

fn login_session(
    login_finish_request: LoginFinishRequestView,
    user: &User,
    now: u64,
    keys: &[EphemeralKey],
    session_key: &SessionKey,
) -> Result<SessionMessage, LoginError> {
    assert_eq!(login_finish_request.user_id, &user.user_id);

    // We want the associated data still in a serialized state here
    let assoc = LoginStartAssociated {
        user_id: login_finish_request.user_id,
        eph_id: login_finish_request.eph_id,
        password_file: &user.password_file.serialize(),
    };
    let decrypted = decrypt_login(
        login_finish_request.eph,
        &assoc.serialize_associated(),
        keys,
    )?;

    // Apparently this ephemeral has already been used!
    if user.state.seen(assoc.eph_id) {
        return Err(LoginError);
    }

    let result = server_login_finish(login_finish_request.message.as_slice(), &decrypted)?;

    // Only if the secrets match do we know login has succeeded!
    if &result.shared_secret != login_finish_request.shared_secret {
        return Err(LoginError);
    }

    // FIXME look at other ways to generate the session id, maybe store it? or some other stuff
    // Instead maybe we can create a way to set an earlier expire time for a user to invalidate all current sessions

    let mut rng = thread_rng();
    let session_id: u128 = rng.gen();
    let authenticated = now;
    let expires = authenticated + SESSION_EXPIRE;
    let session = encrypt_session(
        session_id,
        &user.user_id,
        authenticated,
        expires,
        session_key,
    );

    Ok(SessionMessage {
        session,
        authenticated,
        expires,
    })
}

#[cfg(test)]
mod test {
    use std::time::{self, Instant, UNIX_EPOCH};

    use super::*;
    use crate::session::decrypt_session;
    use crate::{
        test_util::{gen_password_file_with_setup_and_pw, gen_user_name},
        User, UserState,
    };
    use opaque_borink::client::{client_login_finish, client_login_start, ClientStateLogin};
    use opaque_borink::server::ServerSetup;
    use rand::{thread_rng, RngCore};

    // Benchmark indicates the client portion takes around 15-25 ms, while the server portion takes around 180-250 us (microseconds). That is roughly within budget.
    #[test]
    fn test_login() {
        let iters: usize = 1;
        let mut client_time = 0;
        let mut server_time = 0;

        let setup = ServerSetup::create();
        let mut view = setup.view();
        let mut rng = thread_rng();
        let mut session_ids = Vec::new();

        let eph_key = EphemeralKey::create();
        let eph_keys = &[eph_key];
        let eph_key = &eph_keys[0];
        let session_key = SessionKey::create();

        for _ in 0..iters {
            let user_id = gen_user_name();

            let size: usize = rng.gen_range(3..30);
            let mut pw = vec![0u8; size];
            rng.fill_bytes(&mut pw[0..size]);

            let password_file =
                gen_password_file_with_setup_and_pw(&mut view, user_id.as_bytes(), &pw);

            let user = User {
                user_id,
                state: UserState::new(),
                password_file,
                metadata: [0u8; 172],
            };

            let client_now = Instant::now();
            let mut client_state = ClientStateLogin::setup();
            let start = client_login_start(&mut client_state, &pw).unwrap();
            client_time += Instant::now().duration_since(client_now).as_nanos();

            let server_now = Instant::now();
            let start_message = login_start(&mut view, &user, &start.response, eph_key).unwrap();
            let elapsed = Instant::now().duration_since(server_now).as_nanos();
            println!("login start elapsed: {elapsed}");
            server_time += elapsed;

            let client_now = Instant::now();
            let finish =
                client_login_finish(&mut client_state, &pw, &start_message.message).unwrap();
            client_time += Instant::now().duration_since(client_now).as_nanos();

            let server_now = Instant::now();
            let login_finish_request = LoginFinishRequestView {
                message: &finish.response,
                eph: &start_message.eph,
                user_id: &user_id,
                eph_id: start_message.eph_id,
                shared_secret: &finish.shared_secret,
            };

            let now = time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let elapsed = Instant::now().duration_since(server_now).as_nanos();
            println!("get time now elapsed: {elapsed}");
            server_time += elapsed;
            
            let server_now = Instant::now();
            let session =
                login_session(login_finish_request, &user, now, eph_keys, &session_key).unwrap();
            let elapsed = Instant::now().duration_since(server_now).as_nanos();
            println!("login session elapsed: {elapsed}");
            server_time += elapsed;

            let content = decrypt_session(
                &session.session,
                &user_id,
                session.authenticated,
                session.expires,
                &session_key,
            )
            .unwrap();

            session_ids.push(content.session_id);

            assert_eq!(content.user_id, &user_id);
            assert_eq!(content.authenticated, now);
        }

        
        println!("{}", get_benchmark(iters, client_time, "client"));
        println!("{}", get_benchmark(iters, server_time, "server"));

        assert_ne!(session_ids[6.min(iters-1)], 0);
    }

    fn get_benchmark(iters: usize, elapsed_nanos: u128, op_name: &str) -> String {
        let iter_per_elap = (iters as f64) / (elapsed_nanos as f64) * 1_000_000_000f64;

        format!("{op_name}: {} ops/s. {} us/ops",
        iter_per_elap,
        1_000_000f64 / iter_per_elap)
    }
}
