use crate::{
    auth::has_ui_access,
    domain::core::{domain_add, Domain, DomainParam},
    index::Navbar,
};
use askama::Template;
use poem::{
    error::InternalServerError,
    get, handler, post,
    session::Session,
    web::{Data, Form, Html},
    IntoResponse, Request, Response, Route,
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
) -> Result<Response, poem::Error> {
    // Pull username from cookies
    let username: Option<String> = session.get("username");

    // Do we have a user signed in?
    let user: &String = match &username {
        Some(user) => user,
        None => {
            // Render HTML for the UI
            let domain_form: String = DomainForm {
                error: Some("User is not signed in".to_string()),
                has_access: false,
            }
            .render()
            .map_err(InternalServerError)?;

            return Ok(Html(domain_form).into_response());
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

        return Ok(Html(domain_form).into_response());
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

    Ok(Html(domain_form).into_response())
}

/// Tempate for Domain Search Page
#[derive(Template)]
#[template(path = "domain/page/domain_search.html")]
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
    Route::new()
        .at("/domain", post(domain_form))
        .at("/search", get(domain_search))
}
