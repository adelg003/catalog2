use crate::{auth::has_ui_access, domain::DomainForm, index::Navbar};
use askama::Template;
use poem::{
    error::InternalServerError, get, handler, session::Session, web::Html, IntoResponse, Request,
    Response, Route,
};

/// Tempate for Domain Search Page
#[derive(Template)]
#[template(path = "search/page/domain_search.html")]
struct DomainSearch {
    navbar: Navbar,
    domain_add: DomainForm,
}

/// Sign in page
#[handler]
fn domain_search(session: &Session, req: &Request) -> Result<Response, poem::Error> {
    // If we have the username from the cookies, do they have access?
    let username: Option<String> = session.get("username");
    let has_access: bool = match &username {
        Some(username) => has_ui_access(username, req),
        None => false,
    };

    // Render HTML
    let domain_search: String = DomainSearch {
        navbar: Navbar { username },
        domain_add: DomainForm {
            error: None,
            has_access,
        },
    }
    .render()
    .map_err(InternalServerError)?;

    Ok(Html(domain_search).into_response())
}

/// Provide routs for the API endpoints
pub fn route() -> Route {
    Route::new().at("/domain", get(domain_search))
}
