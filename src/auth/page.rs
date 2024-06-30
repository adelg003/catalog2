use crate::{auth::component::SigninForm, index::Navbar};
use askama::Template;
use poem::{
    error::InternalServerError,
    handler,
    http::{header, StatusCode},
    session::Session,
    web::Html,
    IntoResponse, Response,
};

/// Template for Sign In page
#[derive(Template)]
#[template(path = "auth/page/signin.html")]
struct Signin {
    navbar: Navbar,
    signin_form: SigninForm,
}

/// Sign in page
#[handler]
pub fn signin(session: &Session) -> Result<Response, poem::Error> {
    let username: Option<String> = session.get("username");

    // Are we already signed in?
    match username {
        Some(_) => {
            // Redirect back to home page
            Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, "/")
                .finish())
        }
        None => {
            // Ok, we are not signed in
            let signin: String = Signin {
                navbar: Navbar { username: None },
                signin_form: SigninForm { error: None },
            }
            .render()
            .map_err(InternalServerError)?;

            Ok(Html(signin).into_response())
        }
    }
}

/// Logout and purge some cookies
#[handler]
pub fn logout(session: &Session) -> Response {
    session.clear();

    // Redirect back to home page
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, "/")
        .finish()
}
