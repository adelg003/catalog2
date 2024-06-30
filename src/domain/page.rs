use crate::{
    auth::has_ui_access,
    domain::{
        component::{DomainForm, DomainRows},
        core::{search_domain_read, SearchDomain, SearchDomainParam},
    },
    index::Navbar,
};
use askama::Template;
use poem::{
    error::InternalServerError,
    handler,
    session::Session,
    web::{Data, Html},
    IntoResponse, Request, Response,
};
use sqlx::PgPool;

/// Template for Domain Search Page
#[derive(Template)]
#[template(path = "domain/page/domain_search.html")]
struct DomainSearch {
    navbar: Navbar,
    domain_add: DomainForm,
    rows: DomainRows,
}

/// Sign in page
#[handler]
pub async fn domain_search(
    Data(pool): Data<&PgPool>,
    session: &Session,
    req: &Request,
) -> Result<Response, poem::Error> {
    // If we have the username from the cookies, do they have access?
    let username: Option<String> = session.get("username");
    let has_access: bool = match &username {
        Some(username) => has_ui_access(username, req),
        None => false,
    };

    // Start transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Default rows of the domain search
    let domain_search: SearchDomain = search_domain_read(
        &mut tx,
        &SearchDomainParam {
            domain_name: None,
            owner: None,
            extra: None,
        },
        &0,
    )
    .await?;

    // Render HTML
    let domain_search: String = DomainSearch {
        navbar: Navbar { username },
        domain_add: DomainForm {
            error: None,
            has_access,
        },
        rows: DomainRows {
            domains: domain_search.domains,
        },
    }
    .render()
    .map_err(InternalServerError)?;

    Ok(Html(domain_search).into_response())
}
