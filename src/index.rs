use askama::Template;
use poem::{error::InternalServerError, handler, web::Html, Route};

#[derive(Template)]
#[template(path = "index/page/index.html")]
struct Index {}

/// Provide routs for the API endpoints
pub fn route() -> Route {
    Route::new().nest("/", index)
}

#[handler]
async fn index() -> Result<Html<String>, poem::Error> {
    // Render landing page
    let index = Index {}.render().map_err(InternalServerError)?;

    Ok(Html(index))
}
