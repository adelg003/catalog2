use crate::db::{
    domain_drop, domain_insert, domain_select, domain_select_search, domain_update, model_insert,
    model_select, DomainRow, ModelRow,
};
use chrono::{DateTime, Utc};
use poem::{
    error::{BadRequest, Conflict, InternalServerError, NotFound},
    http::StatusCode,
};
use poem_openapi::Object;
use regex::Regex;
use sqlx::PgPool;
use validator::{Validate, ValidationError};

const PAGE_SIZE: u64 = 50;

/// Domain to return via the API
#[derive(Object)]
pub struct Domain {
    id: i32,
    domain: String,
    owner: String,
    extra: serde_json::Value,
    created_by: String,
    created_date: DateTime<Utc>,
    modified_by: String,
    modified_date: DateTime<Utc>,
    //TODO Add models to response
}

impl From<DomainRow> for Domain {
    fn from(domain_row: DomainRow) -> Self {
        Domain {
            id: domain_row.id,
            domain: domain_row.domain,
            owner: domain_row.owner,
            extra: domain_row.extra,
            created_by: domain_row.created_by,
            created_date: domain_row.created_date,
            modified_by: domain_row.modified_by,
            modified_date: domain_row.modified_date,
        }
    }
}

/// How to create a new domain
#[derive(Object, Validate)]
pub struct DomainParam {
    pub domain: String,
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
#[derive(Object)]
pub struct Model {
    id: i32,
    model: String,
    domain_id: i32,
    domain: String,
    owner: String,
    extra: serde_json::Value,
    created_by: String,
    created_date: DateTime<Utc>,
    modified_by: String,
    modified_date: DateTime<Utc>,
    //TODO Add Fields to response
}

impl From<ModelRow> for Model {
    fn from(model_row: ModelRow) -> Self {
        Model {
            id: model_row.id,
            model: model_row.model,
            domain_id: model_row.domain_id,
            domain: model_row.domain,
            owner: model_row.owner,
            extra: model_row.extra,
            created_by: model_row.created_by,
            created_date: model_row.created_date,
            modified_by: model_row.modified_by,
            modified_date: model_row.modified_date,
        }
    }
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

/// How to create a new model
#[derive(Object, Validate)]
pub struct ModelParam {
    #[validate(custom(function = dbx_validater))]
    pub model: String,
    domain: String,
    #[validate(email)]
    pub owner: String,
    pub extra: serde_json::Value,
}

/// Add a domain
pub async fn domain_add(
    pool: &PgPool,
    domain_param: &DomainParam,
    username: &str,
) -> Result<Domain, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    domain_param.validate().map_err(BadRequest)?;

    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Check if domain already exists
    match domain_select(&mut tx, &domain_param.domain).await {
        Ok(_) => Err(poem::Error::from_status(StatusCode::CONFLICT)),
        Err(sqlx::Error::RowNotFound) => Ok(()),
        Err(err) => Err(InternalServerError(err)),
    }?;

    // Add new domain
    domain_insert(&mut tx, domain_param, username)
        .await
        .map_err(InternalServerError)?;

    // Pull value
    let domain: Domain = domain_select(&mut tx, &domain_param.domain)
        .await
        .map_err(InternalServerError)?
        .into();

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(domain)
}

/// Read details of a domain
pub async fn domain_read(pool: &PgPool, domain_name: &str) -> Result<Domain, poem::Error> {
    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Pull domain
    let domain: Domain = domain_select(&mut tx, domain_name)
        .await
        .map_err(NotFound)?
        .into();

    Ok(domain)
}

/// Read details of many domains
pub async fn domain_read_search(
    pool: &PgPool,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
    page: &u64,
) -> Result<DomainSearch, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;
    let next_offset = (page + 1) * PAGE_SIZE;

    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Pull the Domains
    let domain_rows = domain_select_search(
        &mut tx,
        domain_name,
        owner,
        extra,
        &Some(PAGE_SIZE),
        &Some(offset),
    )
    .await
    .map_err(InternalServerError)?;

    // Change from DB Struct to API struct
    let domains: Vec<Domain> = domain_rows.into_iter().map(|row| row.into()).collect();

    // More domains present?
    let next_domain_rows = domain_select_search(
        &mut tx,
        domain_name,
        owner,
        extra,
        &Some(PAGE_SIZE),
        &Some(next_offset),
    )
    .await
    .map_err(InternalServerError)?;

    let more = !next_domain_rows.is_empty();

    Ok(DomainSearch {
        domains,
        page: *page,
        more,
    })
}

/// Edit a Domain
pub async fn domain_edit(
    pool: &PgPool,
    domain_name: &str,
    domain_param: &DomainParam,
    username: &str,
) -> Result<Domain, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    domain_param.validate().map_err(BadRequest)?;

    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Check to make sure domain already exists
    domain_select(&mut tx, domain_name)
        .await
        .map_err(NotFound)?;

    // Update domain
    domain_update(&mut tx, domain_name, domain_param, username)
        .await
        .map_err(Conflict)?;

    // Pull domain
    let domain: Domain = domain_select(&mut tx, &domain_param.domain)
        .await
        .map_err(InternalServerError)?
        .into();

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(domain)
}

/// Remove a Domain
pub async fn domain_remove(pool: &PgPool, domain_name: &str) -> Result<Domain, poem::Error> {
    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Check to make sure domain already exists
    let domain: Domain = domain_select(&mut tx, domain_name)
        .await
        .map_err(NotFound)?
        .into();

    //TODO add cascade

    //TODO - Make sure no models exists for this domain
    //TODO Raise Conflict

    // Delete the domain
    domain_drop(&mut tx, domain_name)
        .await
        .map_err(InternalServerError)?;

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(domain)
}

/// Add a domain
pub async fn model_add(
    pool: &PgPool,
    model_param: &ModelParam,
    username: &str,
) -> Result<Model, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    model_param.validate().map_err(BadRequest)?;

    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Check if model already exists
    match model_select(&mut tx, &model_param.model).await {
        Ok(_) => Err(poem::Error::from_status(StatusCode::CONFLICT)),
        Err(sqlx::Error::RowNotFound) => Ok(()),
        Err(err) => Err(InternalServerError(err)),
    }?;

    // Pull the parent domain
    let domain: Domain = domain_select(&mut tx, &model_param.domain)
        .await
        .map_err(NotFound)?
        .into();

    // Add new model
    model_insert(&mut tx, model_param, &domain.id, username)
        .await
        .map_err(InternalServerError)?;

    // Pull value
    let model: Model = model_select(&mut tx, &model_param.model)
        .await
        .map_err(InternalServerError)?
        .into();

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(model)
}

/// Read details of a model
pub async fn model_read(pool: &PgPool, model_name: &str) -> Result<Model, poem::Error> {
    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Pull model
    let model: Model = model_select(&mut tx, model_name)
        .await
        .map_err(NotFound)?
        .into();

    Ok(model)
}
