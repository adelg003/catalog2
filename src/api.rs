use crate::{
    auth::{make_jwt, Auth, TokenAuth, TokenOrBasicAuth},
    core::{domain_add, domain_read, domain_read_search, Domain, DomainParam},
};
use jsonwebtoken::EncodingKey;
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{
    param::{Path, Query},
    payload::{Json, PlainText},
    OpenApi, Tags,
};
use sqlx::PgPool;

#[derive(Tags)]
enum Tag {
    Auth,
    //TODO Component,
    JsonApi,
}

/// Struct we will build our REST API / Webserver
pub struct Api;

#[OpenApi]
impl Api {
    /// Generate a fresh JWT
    #[oai(path = "/gen_token", method = "post", tag = Tag::Auth)]
    async fn gen_token(
        &self,
        auth: TokenOrBasicAuth,
        Data(encoding_key): Data<&EncodingKey>,
    ) -> Result<PlainText<String>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Get JWT
        let token = make_jwt(username, encoding_key).map_err(InternalServerError)?;

        Ok(PlainText(token))
    }

    /// Add a domain to the domain table
    #[oai(path = "/domain", method = "post", tag = Tag::JsonApi)]
    async fn domain_post(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Json(param): Json<DomainParam>,
    ) -> Result<Json<Domain>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Run Domain add logic
        let domain = domain_add(pool, &param, username).await?;

        Ok(Json(domain))
    }

    /// Get a single domain
    #[oai(path = "/domain/:domain_name", method = "get", tag = Tag::JsonApi)]
    async fn domain_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(domain_name): Path<String>,
    ) -> Result<Json<Domain>, poem::Error> {
        // Pull domain
        let domain = domain_read(pool, &domain_name).await?;

        Ok(Json(domain))
    }

    /// Search domains
    #[oai(path = "/domain_search", method = "get", tag = Tag::JsonApi)]
    async fn domain_get_search(
        &self,
        Data(pool): Data<&PgPool>,
        Query(domain_name): Query<Option<String>>,
        Query(owner): Query<Option<String>>,
        Query(extra): Query<Option<String>>,
        Query(page): Query<Option<u64>>,
    ) -> Result<Json<Vec<Domain>>, poem::Error> {
        // Default no page to 0
        let page = page.unwrap_or(0);

        // Pull domain
        let domains = domain_read_search(pool, &domain_name, &owner, &extra, &page).await?;

        Ok(Json(domains))
    }
}
