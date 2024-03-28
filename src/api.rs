use crate::{
    auth::{make_jwt, Auth, TokenAuth, TokenOrBasicAuth},
    core::{
        domain_add, domain_edit, domain_models_read, domain_read, domain_read_search,
        domain_remove, model_add, model_edit, model_read, model_read_search, model_remove,
        DomainSearch, ModelSearch,
    },
    db::{Domain, DomainModels, DomainParam, Model, ModelParam},
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
    Domain,
    Model,
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
    #[oai(path = "/domain", method = "post", tag = Tag::Domain)]
    async fn domain_post(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Json(domain_param): Json<DomainParam>,
    ) -> Result<Json<Domain>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Run Domain add logic
        let domain = domain_add(pool, &domain_param, username).await?;

        Ok(Json(domain))
    }

    /// Get a single domain
    #[oai(path = "/domain/:domain_name", method = "get", tag = Tag::Domain)]
    async fn domain_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(domain_name): Path<String>,
    ) -> Result<Json<Domain>, poem::Error> {
        // Pull domain
        let domain = domain_read(pool, &domain_name).await?;

        Ok(Json(domain))
    }

    /// Get a single domain and its models
    #[oai(path = "/domain_with_models/:domain_name", method = "get", tag = Tag::Domain)]
    async fn domain_models_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(domain_name): Path<String>,
    ) -> Result<Json<DomainModels>, poem::Error> {
        // Pull domain
        let domain = domain_models_read(pool, &domain_name).await?;

        Ok(Json(domain))
    }

    /// Search domains
    #[oai(path = "/domain_search", method = "get", tag = Tag::Domain)]
    async fn domain_get_search(
        &self,
        Data(pool): Data<&PgPool>,
        Query(domain_name): Query<Option<String>>,
        Query(owner): Query<Option<String>>,
        Query(extra): Query<Option<String>>,
        Query(page): Query<Option<u64>>,
    ) -> Result<Json<DomainSearch>, poem::Error> {
        // Default no page to 0
        let page = page.unwrap_or(0);

        // Pull domain
        let domain_search = domain_read_search(pool, &domain_name, &owner, &extra, &page).await?;

        Ok(Json(domain_search))
    }

    /// Change a domain to the domain table
    #[oai(path = "/domain/:domain_name", method = "put", tag = Tag::Domain)]
    async fn domain_put(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(domain_name): Path<String>,
        Json(domain_param): Json<DomainParam>,
    ) -> Result<Json<Domain>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Run Domain add logic
        let domain = domain_edit(pool, &domain_name, &domain_param, username).await?;

        Ok(Json(domain))
    }

    /// Delete a domain
    #[oai(path = "/domain/:domain_name", method = "delete", tag = Tag::Domain)]
    async fn domain_delete(
        &self,
        Data(pool): Data<&PgPool>,
        Path(domain_name): Path<String>,
    ) -> Result<Json<Domain>, poem::Error> {
        // Pull domain
        let domain = domain_remove(pool, &domain_name).await?;

        Ok(Json(domain))
    }

    /// Add a model to the model table
    #[oai(path = "/model", method = "post", tag = Tag::Model)]
    async fn model_post(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Json(model_param): Json<ModelParam>,
    ) -> Result<Json<Model>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Run Domain add logic
        let model = model_add(pool, &model_param, username).await?;

        Ok(Json(model))
    }

    /// Get a single model
    #[oai(path = "/model/:model_name", method = "get", tag = Tag::Model)]
    async fn model_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
    ) -> Result<Json<Model>, poem::Error> {
        // Pull model
        let model = model_read(pool, &model_name).await?;

        Ok(Json(model))
    }

    /// Search models
    #[oai(path = "/model_search", method = "get", tag = Tag::Model)]
    async fn model_get_search(
        &self,
        Data(pool): Data<&PgPool>,
        Query(model_name): Query<Option<String>>,
        Query(domain_name): Query<Option<String>>,
        Query(owner): Query<Option<String>>,
        Query(extra): Query<Option<String>>,
        Query(page): Query<Option<u64>>,
    ) -> Result<Json<ModelSearch>, poem::Error> {
        // Default no page to 0
        let page = page.unwrap_or(0);

        // Pull models
        let model_search =
            model_read_search(pool, &model_name, &domain_name, &owner, &extra, &page).await?;

        Ok(Json(model_search))
    }

    /// Change a model to the model table
    #[oai(path = "/model/:model_name", method = "put", tag = Tag::Model)]
    async fn model_put(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
        Json(model_param): Json<ModelParam>,
    ) -> Result<Json<Model>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Run Model add logic
        let model = model_edit(pool, &model_name, &model_param, username).await?;

        Ok(Json(model))
    }

    /// Delete a model
    #[oai(path = "/model/:model_name", method = "delete", tag = Tag::Model)]
    async fn model_delete(
        &self,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
    ) -> Result<Json<Model>, poem::Error> {
        // Pull domain
        let model = model_remove(pool, &model_name).await?;

        Ok(Json(model))
    }
}

//TODO Add integration test
