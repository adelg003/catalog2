use crate::{
    auth::{make_jwt, Auth, TokenAuth, TokenOrBasicAuth},
    core::{
        domain_add, domain_edit, domain_read, domain_read_search, domain_read_with_models,
        domain_remove, field_add, field_edit, field_read, field_remove, model_add,
        model_add_with_fields, model_edit, model_read, model_read_search, model_read_with_fields,
        model_remove, model_remove_with_fields, Domain, DomainModels, DomainParam, DomainSearch,
        Field, FieldParam, FieldParamUpdate, Model, ModelFields, ModelFieldsParam, ModelParam,
        ModelSearch,
    },
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
    #[oai(rename = "Domain With Models")]
    DomainWithModels,
    Field,
    Model,
    #[oai(rename = "Model With Fields")]
    ModelWithFields,
    Search,
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

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Run Domain add logic
        let domain = domain_add(&mut tx, &domain_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(domain))
    }

    /// Get a single domain
    #[oai(path = "/domain/:domain_name", method = "get", tag = Tag::Domain)]
    async fn domain_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(domain_name): Path<String>,
    ) -> Result<Json<Domain>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull domain
        let domain = domain_read(&mut tx, &domain_name).await?;

        Ok(Json(domain))
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

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Run Domain add logic
        let domain = domain_edit(&mut tx, &domain_name, &domain_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(domain))
    }

    /// Delete a domain
    #[oai(path = "/domain/:domain_name", method = "delete", tag = Tag::Domain)]
    async fn domain_delete(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(domain_name): Path<String>,
    ) -> Result<Json<Domain>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull domain
        let domain = domain_remove(&mut tx, &domain_name).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(domain))
    }

    /// Get a single domain and its models
    #[oai(path = "/domain_with_models/:domain_name", method = "get", tag = Tag::DomainWithModels)]
    async fn domain_get_with_models(
        &self,
        Data(pool): Data<&PgPool>,
        Path(domain_name): Path<String>,
    ) -> Result<Json<DomainModels>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull domain
        let domain = domain_read_with_models(&mut tx, &domain_name).await?;

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

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Add a model
        let model = model_add(&mut tx, &model_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(model))
    }

    /// Get a single model
    #[oai(path = "/model/:model_name", method = "get", tag = Tag::Model)]
    async fn model_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
    ) -> Result<Json<Model>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull model
        let model = model_read(&mut tx, &model_name).await?;

        Ok(Json(model))
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

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Run Model add logic
        let model = model_edit(&mut tx, &model_name, &model_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(model))
    }

    /// Delete a model
    #[oai(path = "/model/:model_name", method = "delete", tag = Tag::Model)]
    async fn model_delete(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
    ) -> Result<Json<Model>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Delete Model
        let model = model_remove(&mut tx, &model_name).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(model))
    }

    /// Add a model to the model table
    #[oai(path = "/model_with_fields", method = "post", tag = Tag::ModelWithFields)]
    async fn model_post_with_fields(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Json(param): Json<ModelFieldsParam>,
    ) -> Result<Json<ModelFields>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Add a model and its field
        let model_fields = model_add_with_fields(&mut tx, &param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(model_fields))
    }

    /// Get a single model and its fields
    #[oai(path = "/model_with_fields/:model_name", method = "get", tag = Tag::ModelWithFields)]
    async fn model_get_with_fields(
        &self,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
    ) -> Result<Json<ModelFields>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull domain
        let model_fields = model_read_with_fields(&mut tx, &model_name).await?;

        Ok(Json(model_fields))
    }

    /// Delete a model and it s fields
    #[oai(path = "/model_with_fields/:model_name", method = "delete", tag = Tag::ModelWithFields)]
    async fn model_delete_with_fields(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
    ) -> Result<Json<ModelFields>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Delete Model
        let model_fields = model_remove_with_fields(&mut tx, &model_name).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(model_fields))
    }

    /// Add a field to the field table
    #[oai(path = "/field", method = "post", tag = Tag::Field)]
    async fn field_post(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Json(field_param): Json<FieldParam>,
    ) -> Result<Json<Field>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Run Domain add logic
        let field = field_add(&mut tx, &field_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(field))
    }

    /// Get a single field
    #[oai(path = "/field/:model_name/:field_name", method = "get", tag = Tag::Field)]
    async fn field_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
        Path(field_name): Path<String>,
    ) -> Result<Json<Field>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull field
        let field = field_read(&mut tx, &model_name, &field_name).await?;

        Ok(Json(field))
    }

    /// Change a field to the field table
    #[oai(path = "/field/:model_name/:field_name", method = "put", tag = Tag::Field)]
    async fn field_put(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
        Path(field_name): Path<String>,
        Json(field_param): Json<FieldParamUpdate>,
    ) -> Result<Json<Field>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Run Model add logic
        let field = field_edit(&mut tx, &model_name, &field_name, &field_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(field))
    }

    /// Delete a field
    #[oai(path = "/field/:model_name/:field_name", method = "delete", tag = Tag::Field)]
    async fn field_delete(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
        Path(field_name): Path<String>,
    ) -> Result<Json<Field>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Delete Field
        let field = field_remove(&mut tx, &model_name, &field_name).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(field))
    }

    /// Search domains
    #[oai(path = "/search/domain", method = "get", tag = Tag::Search)]
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

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull domain
        let domain_search =
            domain_read_search(&mut tx, &domain_name, &owner, &extra, &page).await?;

        Ok(Json(domain_search))
    }

    /// Search models
    #[oai(path = "/search/model", method = "get", tag = Tag::Search)]
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

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull models
        let model_search =
            model_read_search(&mut tx, &model_name, &domain_name, &owner, &extra, &page).await?;

        Ok(Json(model_search))
    }
}

//TODO Add integration test
