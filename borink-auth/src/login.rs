use crate::User;
use opaque_borink::server::{server_login_start, ServerSetup};

fn login_start(setup: &ServerSetup, user: &User, login_start_request: &[u8]) {
    let mut setup = setup.view();

    let result = server_login_start(&mut setup, &user.password_file, login_start_request, &user.user_id).unwrap();

    //result.state
}

fn login_session() {

}