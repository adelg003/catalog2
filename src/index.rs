use askama::Template;
use poem::{error::InternalServerError, handler, session::Session, web::Html, Route};

#[derive(Template)]
#[template(path = "index/page/index.html")]
struct Index {
    navbar: Navbar,
}

#[derive(Template)]
#[template(path = "shared/component/navbar.html")]
pub struct Navbar {
    pub username: Option<String>,
}

/// Provide routs for the API endpoints
pub fn route() -> Route {
    Route::new().nest("/", index)
}

#[handler]
async fn index(session: &Session) -> Result<Html<String>, poem::Error> {
    // If we have the username from the cookies, use it
    let username: Option<String> = session.get("username");

    // Render landing page
    let index = Index {
        navbar: Navbar { username },
    }
    .render()
    .map_err(InternalServerError)?;

    Ok(Html(index))
}
