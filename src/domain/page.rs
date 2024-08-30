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
    Request,
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
) -> Result<Html<String>, poem::Error> {
    // If we have the username from the cookies, do they have access?
    let username: Option<String> = session.get("username");
    let has_access: bool = match &username {
        Some(username) => has_ui_access(username, req),
        None => false,
    };

    // Start transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Defaults
    let page: u64 = 0;
    let ascending: bool = true;

    // Default rows of the domain search
    let domain_search: SearchDomain = search_domain_read(
        &mut tx,
        &SearchDomainParam {
            domain_name: None,
            owner: None,
            extra: None,
            ascending,
            page,
        },
    )
    .await?;

    // For pagination, here are the next page number
    let next_page: Option<u64> = match &domain_search.more {
        true => Some(page + 1),
        false => None,
    };

    // Render HTML
    let domain_search: String = DomainSearch {
        navbar: Navbar { username },
        domain_add: DomainForm {
            error: None,
            has_access,
        },
        rows: DomainRows {
            domains: domain_search.domains,
            params: SearchDomainParam {
                domain_name: None,
                owner: None,
                extra: None,
                ascending,
                page,
            },
            next_page,
        },
    }
    .render()
    .map_err(InternalServerError)?;

    Ok(Html(domain_search))
}
