use crate::domain::{
    component::{domain_form, domain_rows},
    page::domain_search,
};
use poem::{get, post, Route};

/// Provide routs for the domain pages and components
pub fn route() -> Route {
    Route::new()
        .at("/domain", post(domain_form))
        .at("/search", get(domain_search))
        .at("/search/rows", get(domain_rows))
}
