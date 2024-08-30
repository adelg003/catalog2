use crate::auth::{
    component::signin_form,
    page::{logout, signin},
};
use poem::{get, Route};

/// Provide routs for the API endpoints
pub fn route() -> Route {
    Route::new()
        .at("/signin", get(signin).post(signin_form))
        .at("/logout", get(logout))
}
