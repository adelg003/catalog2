use crate::{
    auth::{make_jwt, Auth},
    core::{domain_add, Domain},
};
use jsonwebtoken::EncodingKey;
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{
    payload::{Json, PlainText},
    Object, OpenApi, Tags,
};
use serde_json::Value;
use sqlx::PgPool;

#[derive(Tags)]
enum Tag {
    Component,
    JsonApi,
}

/// How to create a new domain
#[derive(Object)]
struct DomainPostParam {
    domain: String,
    extra: Value,
}

/// Struct we will build our REST API / Webserver
pub struct Api;

#[OpenApi]
impl Api {
    /// Generate a fresh JWT
    #[oai(path = "/gen_token", method = "post", tag = Tag::JsonApi)]
    async fn gen_token(
        &self,
        auth: Auth,
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
        auth: Auth,
        Data(pool): Data<&PgPool>,
        Json(domain_param): Json<DomainPostParam>,
    ) -> Result<Json<Domain>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Run Domain add logic
        let domain = domain_add(pool, &domain_param.domain, &domain_param.extra, username).await?;

        Ok(Json(domain))
    }
}
