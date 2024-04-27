use crate::{
    auth::{Auth, TokenAuth},
    core::{
        field_add, field_edit, field_read, field_remove, model_add_with_fields,
        model_read_with_fields, model_remove_with_fields, Field, FieldParam, FieldParamUpdate,
        ModelFields, ModelFieldsParam,
    },
};
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{param::Path, payload::Json, OpenApi, Tags};
use sqlx::PgPool;

pub const PAGE_SIZE: u64 = 50;

#[derive(Tags)]
pub enum Tag {
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
}
