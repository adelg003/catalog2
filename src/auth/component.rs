use crate::auth::core::basic_checker;
use askama::Template;
use poem::{
    error::InternalServerError,
    handler,
    http::StatusCode,
    session::Session,
    web::{Form, Html},
    IntoResponse, Request, Response,
};
use poem_openapi::auth::Basic;
use serde::Deserialize;

/// Template for Signin form
#[derive(Template)]
#[template(path = "auth/component/signin_form.html")]
pub struct SigninForm {
    pub error: Option<String>,
}

#[derive(Deserialize)]
struct SigninParams {
    username: String,
    password: String,
}

/// Signin form for the UI
#[handler]
pub async fn signin_form(
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
