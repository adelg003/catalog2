use crate::{auth::core::basic_checker, index::Navbar};
use askama::Template;
use poem::{
    error::InternalServerError,
    get, handler,
    http::{header, StatusCode},
    session::Session,
    web::{Form, Html},
    IntoResponse, Request, Response, Route,
};
use poem_openapi::auth::Basic;
use serde::Deserialize;

/// Tempate for Signin page
#[derive(Template)]
#[template(path = "auth/page/signin.html")]
struct Signin {
    navbar: Navbar,
    signin_form: SigninForm,
}

/// Sign in page
#[handler]
fn signin(session: &Session) -> Result<Response, poem::Error> {
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

/// Tempate for Signin form
#[derive(Template)]
#[template(path = "auth/component/signin_form.html")]
struct SigninForm {
    error: Option<String>,
}

#[derive(Deserialize)]
struct SigninParams {
    username: String,
    password: String,
}

/// Signin form for the UI
#[handler]
async fn signin_form(
    Form(params): Form<SigninParams>,
    session: &Session,
    req: &Request,
) -> Result<Response, poem::Error> {
    let basic = Basic {
        username: params.username,
        password: params.password,
    };
    // Do the creds match what we are expecting?
    match basic_checker(req, basic).await {
        Some(user) => {
            // Save the username if auth is good
            session.set("username", user.username);

            // Redirect back to home page
            Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header("HX-Redirect", "/")
                .finish())
        }
        None => {
            // Well, looks like user auth failed
            let signin_form: String = SigninForm {
                error: Some("User authentiation failed".to_string()),
            }
            .render()
            .map_err(InternalServerError)?;

            Ok(Html(signin_form).into_response())
        }
    }
}

/// Logout and purge some cookies
#[handler]
fn logout(session: &Session) -> Response {
    session.clear();

    // Redirect back to home page
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, "/")
        .finish()
}

/// Provide routs for the API endpoints
pub fn route() -> Route {
    Route::new()
        .at("/signin", get(signin).post(signin_form))
        .at("/logout", get(logout))
}
