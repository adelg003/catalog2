use crate::db::{
    domain_drop, domain_insert, domain_select, domain_select_search, domain_update, field_drop,
    field_drop_by_model, field_insert, field_select, field_select_by_model, field_update,
    model_drop, model_insert, model_select, model_select_by_domain, model_select_search,
    model_update,
};
use chrono::{DateTime, Utc};
use poem::{
    error::{BadRequest, Conflict, InternalServerError, NotFound},
    http::StatusCode,
};
use poem_openapi::{Enum, Object};
use regex::Regex;
use sqlx::{FromRow, Postgres, Transaction, Type};
use validator::{Validate, ValidationError};

const PAGE_SIZE: u64 = 50;

/// Domain Shared
#[derive(Debug, FromRow, Object)]
pub struct Domain {
    pub id: i32,
    pub name: String,
    pub owner: String,
    pub extra: serde_json::Value,
    pub created_by: String,
    pub created_date: DateTime<Utc>,
    pub modified_by: String,
    pub modified_date: DateTime<Utc>,
}

impl Domain {
    /// Add model details to a domain
    pub async fn add_models(
        self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<DomainModels, poem::Error> {
        // Pull models
        let models = model_select_by_domain(tx, &self.name)
            .await
            .map_err(InternalServerError)?;

        Ok(DomainModels {
            domain: self,
            models,
        })
    }
}

/// How to create a new domain
#[derive(Debug, Object, Validate)]
pub struct DomainParam {
    #[validate(custom(function = dbx_validater))]
    pub name: String,
    #[validate(email)]
    pub owner: String,
    pub extra: serde_json::Value,
}

/// Domain Search Results
#[derive(Object)]
pub struct DomainSearch {
    domains: Vec<Domain>,
    page: u64,
    more: bool,
}

/// Model to return via the API
#[derive(FromRow, Object)]
pub struct Model {
    pub id: i32,
    pub name: String,
    pub domain_id: i32,
    pub domain_name: String,
    pub owner: String,
    pub extra: serde_json::Value,
    pub created_by: String,
    pub created_date: DateTime<Utc>,
    pub modified_by: String,
    pub modified_date: DateTime<Utc>,
}

impl Model {
    /// Add fields details to a model
    pub async fn add_fields(
        self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<ModelFields, poem::Error> {
        // Pull models
        let fields = field_select_by_model(tx, &self.name)
            .await
            .map_err(InternalServerError)?;

        Ok(ModelFields {
            model: self,
            fields,
        })
    }
}

/// How to create a new model
#[derive(Object, Validate)]
pub struct ModelParam {
    #[validate(custom(function = dbx_validater))]
    pub name: String,
    pub domain_name: String,
    #[validate(email)]
    pub owner: String,
    pub extra: serde_json::Value,
}

/// Model Search Results
#[derive(Object)]
pub struct ModelSearch {
    models: Vec<Model>,
    page: u64,
    more: bool,
}

/// Domain with models
#[derive(Object)]
pub struct DomainModels {
    domain: Domain,
    models: Vec<Model>,
}

/// Databrick Dataypes
/// https://learn.microsoft.com/en-us/azure/databricks/sql/language-manual/sql-ref-datatypes
#[derive(Clone, Copy, Enum, Type)]
#[oai(rename_all = "lowercase")]
#[sqlx(type_name = "dbx_data_type", rename_all = "lowercase")]
pub enum DbxDataType {
    BigInt,
    Binary,
    Boolean,
    Date,
    Decimal,
    Double,
    Float,
    Int,
    Interval,
    Void,
    SmallInt,
    String,
    Timestamp,
    TimestampNtz,
    TinyInt,
}

/// Field to return via the API
#[derive(FromRow, Object)]
pub struct Field {
    pub id: i32,
    pub name: String,
    pub model_id: i32,
    pub model_name: String,
    pub seq: Option<i64>,
    pub is_primary: bool,
    pub data_type: DbxDataType,
    pub is_nullable: bool,
    pub precision: Option<i32>,
    pub scale: Option<i32>,
    pub extra: serde_json::Value,
    pub created_by: String,
    pub created_date: DateTime<Utc>,
    pub modified_by: String,
    pub modified_date: DateTime<Utc>,
}

/// How to create a new model
#[derive(Object, Validate)]
pub struct FieldParam {
    pub name: String,
    pub model_name: String,
    pub is_primary: bool,
    pub data_type: DbxDataType,
    pub is_nullable: bool,
    pub precision: Option<i32>,
    pub scale: Option<i32>,
    pub extra: serde_json::Value,
}

impl FieldParam {
    /// Ensure only decimals get the precision and scale parameters
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate model and field names
        dbx_validater(&self.name)?;
        dbx_validater(&self.model_name)?;

        // Validate dtype parameters
        validate_data_type(&self.data_type, &self.precision, &self.scale)?;

        Ok(())
    }
}

/// How to update an existing model
#[derive(Object, Validate)]
pub struct FieldParamUpdate {
    pub name: String,
    pub is_primary: bool,
    pub data_type: DbxDataType,
    pub is_nullable: bool,
    pub precision: Option<i32>,
    pub scale: Option<i32>,
    pub extra: serde_json::Value,
}

impl FieldParamUpdate {
    /// Ensure only decimals get the precision and scale parameters
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate model and field names
        dbx_validater(&self.name)?;

        // Validate dtype parameters
        validate_data_type(&self.data_type, &self.precision, &self.scale)?;

        Ok(())
    }
}

/// Validate Datatype in Field
fn validate_data_type(
    data_type: &DbxDataType,
    precision: &Option<i32>,
    scale: &Option<i32>,
) -> Result<(), ValidationError> {
    // Validate dtype parameters
    match (data_type, precision, scale) {
        (DbxDataType::Decimal, Some(_), Some(_)) => Ok(()),
        (
            DbxDataType::BigInt
            | DbxDataType::Binary
            | DbxDataType::Boolean
            | DbxDataType::Date
            | DbxDataType::Double
            | DbxDataType::Float
            | DbxDataType::Int
            | DbxDataType::Interval
            | DbxDataType::Void
            | DbxDataType::SmallInt
            | DbxDataType::String
            | DbxDataType::Timestamp
            | DbxDataType::TimestampNtz
            | DbxDataType::TinyInt,
            None,
            None,
        ) => Ok(()),
        _ => Err(ValidationError::new(
            "Only Deciaml data type should have scale and precision",
        )),
    }
}

/// Field Search Results
#[derive(Object)]
pub struct FieldSearch {
    fields: Vec<Field>,
    page: u64,
    more: bool,
}

/// Model with fields
#[derive(Object)]
pub struct ModelFields {
    model: Model,
    fields: Vec<Field>,
}

/// Model with field parameters
#[derive(Object)]
pub struct ModelFieldsParam {
    model: ModelParam,
    fields: Vec<FieldParamModelChild>,
}

/// How to create a new field if bundled with the models
#[derive(Object)]
pub struct FieldParamModelChild {
    pub name: String,
    pub is_primary: bool,
    pub data_type: DbxDataType,
    pub is_nullable: bool,
    pub precision: Option<i32>,
    pub scale: Option<i32>,
    pub extra: serde_json::Value,
}

/// Only allow for valid DBX name, meaning letters, number, dashes, and underscores. First
/// character needs to be a letter. Also, since DBX is case-insensitive, only allow lower
/// characters to ensure unique constraints work.
fn dbx_validater(obj_name: &str) -> Result<(), ValidationError> {
    let dbx_regex = Regex::new("^[a-z][a-z0-9_-]*$");
    match dbx_regex {
        Ok(re) if re.is_match(obj_name) => Ok(()),
        _ => Err(ValidationError::new("Failed DBX Regex Check")),
    }
}

/// Add a domain
pub async fn domain_add(
    tx: &mut Transaction<'_, Postgres>,
    domain_param: &DomainParam,
    username: &str,
) -> Result<Domain, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    domain_param.validate().map_err(BadRequest)?;

    // Add new domain
    let domain = domain_insert(tx, domain_param, username)
        .await
        .map_err(Conflict)?;

    Ok(domain)
}

/// Read details of a domain
pub async fn domain_read(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<Domain, poem::Error> {
    // Pull domain
    let domain = domain_select(tx, domain_name).await.map_err(NotFound)?;

    Ok(domain)
}

/// Read details of a domain and add model details for that domain
pub async fn domain_read_with_models(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<DomainModels, poem::Error> {
    // Pull domain_models
    let domain_models = domain_select(tx, domain_name)
        .await
        .map_err(NotFound)?
        .add_models(tx)
        .await?;

    Ok(domain_models)
}

/// Read details of many domains
pub async fn domain_read_search(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
    page: &u64,
) -> Result<DomainSearch, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;
    let next_offset = (page + 1) * PAGE_SIZE;

    // Pull the Domains
    let domains = domain_select_search(
        tx,
        domain_name,
        owner,
        extra,
        &Some(PAGE_SIZE),
        &Some(offset),
    )
    .await
    .map_err(InternalServerError)?;

    // More domains present?
    let next_domain = domain_select_search(
        tx,
        domain_name,
        owner,
        extra,
        &Some(PAGE_SIZE),
        &Some(next_offset),
    )
    .await
    .map_err(InternalServerError)?;

    let more = !next_domain.is_empty();

    Ok(DomainSearch {
        domains,
        page: *page,
        more,
    })
}

/// Edit a Domain
pub async fn domain_edit(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
    domain_param: &DomainParam,
    username: &str,
) -> Result<Domain, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    domain_param.validate().map_err(BadRequest)?;

    // Update domain
    let update = domain_update(tx, domain_name, domain_param, username).await;

    // What result did we get?
    let domain = match update {
        Ok(domain) => Ok(domain),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    Ok(domain)
}

/// Remove a Domain
pub async fn domain_remove(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
    //cascade: &bool,
) -> Result<Domain, poem::Error> {
    // Delete the domain
    let delete = domain_drop(tx, domain_name).await;

    // What result did we get?
    let domain = match delete {
        Ok(domain) => Ok(domain),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    Ok(domain)
}

/// Add a model
pub async fn model_add(
    tx: &mut Transaction<'_, Postgres>,
    model_param: &ModelParam,
    username: &str,
) -> Result<Model, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    model_param.validate().map_err(BadRequest)?;

    // Add Model
    let insert = model_insert(tx, model_param, username).await;

    // What result did we get?
    let model = match insert {
        Ok(model) => Ok(model),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    Ok(model)
}

/// Read details of a model
pub async fn model_read(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Model, poem::Error> {
    // Pull model
    let model: Model = model_select(tx, model_name).await.map_err(NotFound)?;

    Ok(model)
}

/// Read details of many models
pub async fn model_read_search(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &Option<String>,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
    page: &u64,
) -> Result<ModelSearch, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;
    let next_offset = (page + 1) * PAGE_SIZE;

    // Pull the Models
    let models = model_select_search(
        tx,
        model_name,
        domain_name,
        owner,
        extra,
        &Some(PAGE_SIZE),
        &Some(offset),
    )
    .await
    .map_err(InternalServerError)?;

    // More domains present?
    let next_model = model_select_search(
        tx,
        model_name,
        domain_name,
        owner,
        extra,
        &Some(PAGE_SIZE),
        &Some(next_offset),
    )
    .await
    .map_err(InternalServerError)?;

    let more = !next_model.is_empty();

    Ok(ModelSearch {
        models,
        page: *page,
        more,
    })
}
/// Edit a Model
pub async fn model_edit(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    model_param: &ModelParam,
    username: &str,
) -> Result<Model, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    model_param.validate().map_err(BadRequest)?;

    // Update domain
    let update = model_update(tx, model_name, model_param, username).await;

    // What result did we get?
    let model = match update {
        Ok(model) => Ok(model),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain or model does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    Ok(model)
}

/// Remove a Model
pub async fn model_remove(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Model, poem::Error> {
    // Delete the model
    let model = model_drop(tx, model_name).await.map_err(NotFound)?;

    Ok(model)
}

/// Add a model with fields
pub async fn model_add_with_fields(
    tx: &mut Transaction<'_, Postgres>,
    param: &ModelFieldsParam,
    username: &str,
) -> Result<ModelFields, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    param.model.validate().map_err(BadRequest)?;

    // Add Model
    let model_insert = model_insert(tx, &param.model, username).await;

    // What result did we get?
    let model = match model_insert {
        Ok(model) => Ok(model),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    // Add Fields
    let mut fields = Vec::new();
    for wip in &param.fields {
        // Map to the full FieldParam
        let field_param = FieldParam {
            name: wip.name.clone(),
            model_name: model.name.clone(),
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
        let field_insert = field_insert(tx, &field_param, username).await;

        // What result did we get?
        let field = match field_insert {
            Ok(field) => Ok(field),
            // If this happens after just inserting a model, then its an us issue.
            Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
                "model does not exist",
                StatusCode::INTERNAL_SERVER_ERROR,
            )),
            Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
            Err(err) => Err(InternalServerError(err)),
        }?;

        fields.push(field);
    }

    Ok(ModelFields { model, fields })
}

/// Read details of a model and add fields details for that model
pub async fn model_read_with_fields(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<ModelFields, poem::Error> {
    // Pull domain_models
    let model_fields = model_select(tx, model_name)
        .await
        .map_err(NotFound)?
        .add_fields(tx)
        .await?;

    Ok(model_fields)
}

/// Delete a model with all its fields
pub async fn model_remove_with_fields(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<ModelFields, poem::Error> {
    // Delete all the fields
    let fields = field_drop_by_model(tx, model_name)
        .await
        .map_err(NotFound)?;

    // Delete the model
    let model = model_drop(tx, model_name).await.map_err(NotFound)?;

    Ok(ModelFields { model, fields })
}

/// Add a field
pub async fn field_add(
    tx: &mut Transaction<'_, Postgres>,
    field_param: &FieldParam,
    username: &str,
) -> Result<Field, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    field_param.validate().map_err(BadRequest)?;

    // Add Field
    let insert = field_insert(tx, field_param, username).await;

    // What result did we get?
    let field = match insert {
        Ok(field) => Ok(field),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "model does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    Ok(field)
}

/// Read details of a field
pub async fn field_read(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    field_name: &str,
) -> Result<Field, poem::Error> {
    // Pull field
    let field = field_select(tx, model_name, field_name)
        .await
        .map_err(NotFound)?;

    Ok(field)
}

/// Edit a Field
pub async fn field_edit(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    field_name: &str,
    field_param: &FieldParamUpdate,
    username: &str,
) -> Result<Field, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    field_param.validate().map_err(BadRequest)?;

    // Update domain
    let update = field_update(tx, model_name, field_name, field_param, username).await;

    // What result did we get?
    let field = match update {
        Ok(field) => Ok(field),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "model or field does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    Ok(field)
}

/// Remove a Field
pub async fn field_remove(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    field_name: &str,
) -> Result<Field, poem::Error> {
    // Delete the field
    let field = field_drop(tx, model_name, field_name)
        .await
        .map_err(NotFound)?;

    Ok(field)
}

//TODO Add Unit Tes
