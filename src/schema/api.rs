use crate::{
    api::Tag,
    auth::{Auth, TokenAuth},
    schema::core::{
        schema_add, schema_add_with_fields, schema_edit, schema_read, schema_read_with_fields,
        schema_read_with_models, schema_remove, schema_remove_with_fields, search_schema_read,
        Schema, SchemaFields, SchemaFieldsParam, SchemaModels, SchemaParam, SearchSchema,
        SearchSchemaParam,
    },
};
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{
    param::{Path, Query},
    payload::Json,
    OpenApi,
};
use sqlx::PgPool;

/// Struct we will build our REST API / Webserver
pub struct SchemaApi;

#[OpenApi]
impl SchemaApi {
    /// Add a schema to the schema table
    #[oai(path = "/schema", method = "post", tag = Tag::Schema)]
    async fn schema_post(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Json(schema_param): Json<SchemaParam>,
    ) -> Result<Json<Schema>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Add a schema
        let schema = schema_add(&mut tx, &schema_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(schema))
    }

    /// Get a single schema
    #[oai(path = "/schema/:schema_name", method = "get", tag = Tag::Schema)]
    async fn schema_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(schema_name): Path<String>,
    ) -> Result<Json<Schema>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull schema
        let schema = schema_read(&mut tx, &schema_name).await?;

        Ok(Json(schema))
    }

    /// Change a schema to the modeschemale
    #[oai(path = "/schema/:schema_name", method = "put", tag = Tag::Schema)]
    async fn schema_put(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(schema_name): Path<String>,
        Json(schema_param): Json<SchemaParam>,
    ) -> Result<Json<Schema>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Run Schema add logic
        let schema = schema_edit(&mut tx, &schema_name, &schema_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(schema))
    }

    /// Delete a schema
    #[oai(path = "/schema/:schema_name", method = "delete", tag = Tag::Schema)]
    async fn schema_delete(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(schema_name): Path<String>,
    ) -> Result<Json<Schema>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Delete Schema
        let schema = schema_remove(&mut tx, &schema_name).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(schema))
    }

    /// Add a schema to the schema table
    #[oai(path = "/schema_with_fields", method = "post", tag = Tag::SchemaWithFields)]
    async fn schema_post_with_fields(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Json(param): Json<SchemaFieldsParam>,
    ) -> Result<Json<SchemaFields>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Add a schema and its field
        let schema_fields = schema_add_with_fields(&mut tx, &param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(schema_fields))
    }

    /// Get a single schema and its fields
    #[oai(path = "/schema_with_fields/:schema_name", method = "get", tag = Tag::SchemaWithFields)]
    async fn schema_get_with_fields(
        &self,
        Data(pool): Data<&PgPool>,
        Path(schema_name): Path<String>,
    ) -> Result<Json<SchemaFields>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull domain
        let schema_fields = schema_read_with_fields(&mut tx, &schema_name).await?;

        Ok(Json(schema_fields))
    }

    /// Delete a schema and it s fields
    #[oai(path = "/schema_with_fields/:schema_name", method = "delete", tag = Tag::SchemaWithFields)]
    async fn schema_delete_with_fields(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(schema_name): Path<String>,
    ) -> Result<Json<SchemaFields>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Delete Schema
        let schema_fields = schema_remove_with_fields(&mut tx, &schema_name).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(schema_fields))
    }

    /// Get a single schema and its models
    #[oai(path = "/schema_with_models/:schema_name", method = "get", tag = Tag::SchemaWithModels)]
    async fn schema_get_with_models(
        &self,
        Data(pool): Data<&PgPool>,
        Path(schema_name): Path<String>,
    ) -> Result<Json<SchemaModels>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull domain
        let schema_models = schema_read_with_models(&mut tx, &schema_name).await?;

        Ok(Json(schema_models))
    }
    /// Search schemas
    #[oai(path = "/search/schema", method = "get", tag = Tag::Search)]
    async fn search_schema_get(
        &self,
        Data(pool): Data<&PgPool>,
        Query(schema_name): Query<Option<String>>,
        Query(owner): Query<Option<String>>,
        Query(extra): Query<Option<String>>,
        Query(page): Query<Option<u64>>,
    ) -> Result<Json<SearchSchema>, poem::Error> {
        // Default no page to 0
        let page = page.unwrap_or(0);

        // Search Params
        let search_param = SearchSchemaParam {
            schema_name,
            owner,
            extra,
        };

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull schemas
        let search_schema = search_schema_read(&mut tx, &search_param, &page).await?;

        Ok(Json(search_schema))
    }
}
