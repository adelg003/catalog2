use crate::{
    field::{field_add, DbxDataType, Field, FieldParam},
    model::Model,
    schema::db::{
        field_drop_by_schema, field_select_by_schema, model_select_by_schema, schema_drop,
        schema_insert, schema_select, schema_update, search_schema_select,
    },
    util::{dbx_validater, PAGE_SIZE},
};
use chrono::{DateTime, Utc};
use poem::{
    error::{BadRequest, Conflict, InternalServerError, NotFound},
    http::StatusCode,
};
use poem_openapi::Object;
use serde::Serialize;
use sqlx::{FromRow, Postgres, Transaction};
use validator::Validate;

/// Schema to return via the API
#[derive(Debug, FromRow, Object)]
pub struct Schema {
    pub id: i32,
    pub name: String,
    pub owner: String,
    pub extra: serde_json::Value,
    pub created_by: String,
    pub created_date: DateTime<Utc>,
    pub modified_by: String,
    pub modified_date: DateTime<Utc>,
}

/// How to create a new schema
#[derive(Debug, Object, Serialize, Validate)]
pub struct SchemaParam {
    #[validate(custom(function = dbx_validater))]
    pub name: String,
    #[validate(email)]
    pub owner: String,
    pub extra: serde_json::Value,
}

/// Schema with fields
#[derive(Object)]
pub struct SchemaFields {
    pub schema: Schema,
    pub fields: Vec<Field>,
}

/// Schema with field parameters
#[derive(Object)]
pub struct SchemaFieldsParam {
    schema: SchemaParam,
    fields: Vec<FieldParamSchemaChild>,
}

/// Schema with Models
#[derive(Object)]
pub struct SchemaModels {
    pub schema: Schema,
    pub models: Vec<Model>,
}

/// How to create a new field if bundled with the schema
#[derive(Object)]
pub struct FieldParamSchemaChild {
    pub name: String,
    pub is_primary: bool,
    pub data_type: DbxDataType,
    pub is_nullable: bool,
    pub precision: Option<i32>,
    pub scale: Option<i32>,
    pub extra: serde_json::Value,
}

/// Schema Search Results
#[derive(Object)]
pub struct SearchSchema {
    schemas: Vec<Schema>,
    page: u64,
    more: bool,
}

/// Params for searching for schemas
pub struct SearchSchemaParam {
    pub schema_name: Option<String>,
    pub owner: Option<String>,
    pub extra: Option<String>,
}

/// Add a schema
pub async fn schema_add(
    tx: &mut Transaction<'_, Postgres>,
    schema_param: &SchemaParam,
    username: &str,
) -> Result<Schema, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    schema_param.validate().map_err(BadRequest)?;

    // Add Schema
    schema_insert(tx, schema_param, username)
        .await
        .map_err(Conflict)
}

/// Read details of a schema
pub async fn schema_read(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
) -> Result<Schema, poem::Error> {
    // Pull schema
    schema_select(tx, schema_name).await.map_err(NotFound)
}

/// Edit a Schema
pub async fn schema_edit(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
    schema_param: &SchemaParam,
    username: &str,
) -> Result<Schema, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    schema_param.validate().map_err(BadRequest)?;

    // Update domain
    let update = schema_update(tx, schema_name, schema_param, username).await;

    // What result did we get?
    match update {
        Ok(schema) => Ok(schema),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "schema does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }
}

/// Remove a Schema
pub async fn schema_remove(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
) -> Result<Schema, poem::Error> {
    // Delete the schema
    let delete = schema_drop(tx, schema_name).await;

    // What result did we get?
    match delete {
        Ok(schema) => Ok(schema),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "schema does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }
}

/// Add a schema with fields
pub async fn schema_add_with_fields(
    tx: &mut Transaction<'_, Postgres>,
    param: &SchemaFieldsParam,
    username: &str,
) -> Result<SchemaFields, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    param.schema.validate().map_err(BadRequest)?;

    // Add Schema
    let schema = schema_add(tx, &param.schema, username).await?;

    // Add Fields
    let mut fields = Vec::new();
    for wip in &param.fields {
        // Map to the full FieldParam
        let field_param = FieldParam {
            name: wip.name.clone(),
            schema_name: schema.name.clone(),
            is_primary: wip.is_primary,
            data_type: wip.data_type,
            is_nullable: wip.is_nullable,
            precision: wip.precision,
            scale: wip.scale,
            extra: wip.extra.clone(),
        };

        // Make sure the payload we got is good (check with Validate package).
        field_param.validate().map_err(BadRequest)?;

        // Insert the field
        let field = field_add(tx, &field_param, username).await?;

        fields.push(field);
    }

    Ok(SchemaFields { schema, fields })
}

/// Read details of a schema and add fields details for that schema
pub async fn schema_read_with_fields(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
) -> Result<SchemaFields, poem::Error> {
    // Pull schema
    let schema = schema_read(tx, schema_name).await?;

    // Pull models
    let fields = field_select_by_schema(tx, schema_name)
        .await
        .map_err(InternalServerError)?;

    Ok(SchemaFields { schema, fields })
}

/// Delete a schema with all its fields
pub async fn schema_remove_with_fields(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
) -> Result<SchemaFields, poem::Error> {
    // Delete all the fields
    let fields = field_drop_by_schema(tx, schema_name)
        .await
        .map_err(InternalServerError)?;

    // Delete the schema
    let schema = schema_remove(tx, schema_name).await?;

    Ok(SchemaFields { schema, fields })
}

/// Read details of a schema and add model details for that schema
pub async fn schema_read_with_models(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
) -> Result<SchemaModels, poem::Error> {
    // Pull schema
    let schema = schema_read(tx, schema_name).await?;

    // Pull models
    let models = model_select_by_schema(tx, schema_name)
        .await
        .map_err(InternalServerError)?;

    Ok(SchemaModels { schema, models })
}

/// Read details of many schemas
pub async fn search_schema_read(
    tx: &mut Transaction<'_, Postgres>,
    search_param: &SearchSchemaParam,
    page: &u64,
) -> Result<SearchSchema, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;
    let next_offset = (page + 1) * PAGE_SIZE;

    // Pull the Schemas
    let schemas = search_schema_select(tx, search_param, &Some(PAGE_SIZE), &Some(offset))
        .await
        .map_err(InternalServerError)?;

    // More schemas present?
    let next_schema = search_schema_select(tx, search_param, &Some(PAGE_SIZE), &Some(next_offset))
        .await
        .map_err(InternalServerError)?;

    let more = !next_schema.is_empty();

    Ok(SearchSchema {
        schemas,
        page: *page,
        more,
    })
}
