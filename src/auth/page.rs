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
struct Signin<'a> {
    navbar: Navbar,
    signin_form: SigninForm<'a>,
}

/// Sign in page
#[handler]
fn signin(session: &Session) -> Result<Response, poem::Error> {
    let username: Option<String> = session.get("username");

    // Are we already signed in?
    if username.is_some() {
        // Redirect back to home page
        Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/")
            .finish())
    } else {
        // Ok, we are not signed in
        let signin_html: String = Signin {
            navbar: Navbar { username: None },
            signin_form: SigninForm { error: None },
        }
        .render()
        .map_err(InternalServerError)?;

        Ok(Html(signin_html).into_response())
    }
}

/// Tempate for Signin form
#[derive(Template)]
#[template(path = "auth/component/signin_form.html")]
struct SigninForm<'a> {
    error: Option<&'a str>,
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
    if let Some(user) = basic_checker(req, basic).await {
        // Save the username if auth is good
        session.set("username", user.username);

        // Redirect back to home page
        Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/")
            .finish())
    } else {
        // Well, looks like user auth failed
        let signin_form_html: String = SigninForm {
            error: Some("User authentiation failed"),
        }
        .render()
        .map_err(InternalServerError)?;

        Ok(Html(signin_form_html).into_response())
    }
}

/// Logout and purge some cookies
#[handler]
async fn logout(session: &Session) -> Response {
    session.purge();

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
