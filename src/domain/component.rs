use crate::{
    auth::has_ui_access,
    domain::core::{
        domain_add, search_domain_read, Domain, DomainParam, SearchDomain, SearchDomainParam,
    },
};
use askama::Template;
use poem::{
    error::InternalServerError,
    handler,
    session::Session,
    web::{Data, Form, Html, Query},
    Request,
};
use sqlx::PgPool;

/// Tempate to add a Domain
#[derive(Template)]
#[template(path = "domain/component/domain_form.html")]
pub struct DomainForm {
    pub error: Option<String>,
    pub has_access: bool,
}

/// Add a Domain via the UI
#[handler]
pub async fn domain_form(
    Data(pool): Data<&PgPool>,
    Form(params): Form<DomainParam>,
    session: &Session,
    req: &Request,
) -> Result<Html<String>, poem::Error> {
    // Pull username from cookies
    let username: Option<String> = session.get("username");

    // Do we have a user signed in?
    let user: &str = match &username {
        Some(user) => user,
        None => {
            // Render HTML for the UI
            let domain_form: String = DomainForm {
                error: Some("User is not signed in".to_string()),
                has_access: false,
            }
            .render()
            .map_err(InternalServerError)?;

            return Ok(Html(domain_form));
        }
    };

    // Does the user have access?
    let has_access: bool = has_ui_access(user, req);
    if !has_access {
        // Render HTML for the UI
        let domain_form: String = DomainForm {
            error: Some("User does not have access".to_string()),
            has_access,
        }
        .render()
        .map_err(InternalServerError)?;

        return Ok(Html(domain_form));
    }

    // Start transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Write new Domain to the DB
    let domain: Result<Domain, poem::Error> = domain_add(&mut tx, &params, user).await;

    // Did we get any errors writing to the DB?
    let error = match domain {
        Ok(_) => {
            tx.commit().await.map_err(InternalServerError)?;
            None
        }
        Err(err) => {
            tx.rollback().await.map_err(InternalServerError)?;
            Some(err.to_string())
        }
    };

    // Render HTML for the UI
    let domain_form: String = DomainForm { error, has_access }
        .render()
        .map_err(InternalServerError)?;

    Ok(Html(domain_form))
}

/// Tempate for rows od Domains
#[derive(Template)]
#[template(path = "domain/component/domain_rows.html")]
pub struct DomainRows {
    pub domains: Vec<Domain>,
}

/// Results of searching for a domain
#[handler]
pub async fn domain_rows(
    Data(pool): Data<&PgPool>,
    Query(params): Query<SearchDomainParam>,
) -> Result<Html<String>, poem::Error> {
    // Start transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Default rows of the domain search
    let domain_search: SearchDomain = search_domain_read(&mut tx, &params, &0).await?;

    let rows: String = DomainRows {
        domains: domain_search.domains,
    }
    .render()
    .map_err(InternalServerError)?;

    Ok(Html(rows))
}
