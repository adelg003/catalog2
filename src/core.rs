use crate::db::{
    domain_count, domain_drop, domain_insert, domain_select, domain_select_search, domain_update,
};
use chrono::{DateTime, Utc};
use poem::{
    error::{BadRequest, Conflict, InternalServerError, NotFound},
    http::StatusCode,
};
use poem_openapi::Object;
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use validator::Validate;

const PAGE_SIZE: u64 = 50;

/// Shared Domain struct
#[derive(FromRow, Object)]
pub struct Domain {
    pub id: i32,
    pub domain: String,
    pub owner: String,
    pub extra: Value,
    pub created_by: String,
    pub created_date: DateTime<Utc>,
    pub modified_by: String,
    pub modified_date: DateTime<Utc>,
}

/// How to create a new domain
#[derive(Object, Validate)]
pub struct DomainParam {
    pub domain: String,
    #[validate(email)]
    pub owner: String,
    pub extra: Value,
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
    let count = domain_count(&mut tx, &domain_param.domain)
        .await
        .map_err(InternalServerError)?;
    if count >= 1 {
        return Err(poem::Error::from_status(StatusCode::CONFLICT));
    }

    // Add new domain
    domain_insert(&mut tx, domain_param, username)
        .await
        .map_err(InternalServerError)?;

    // Pull value
    let domain = domain_select(&mut tx, &domain_param.domain)
        .await
        .map_err(InternalServerError)?;

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(domain)
}

/// Read details of a domain
pub async fn domain_read(pool: &PgPool, domain_name: &str) -> Result<Domain, poem::Error> {
    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Pull domain
    let domain = domain_select(&mut tx, domain_name)
        .await
        .map_err(NotFound)?;

    Ok(domain)
}

/// Read details of many domains
pub async fn domain_read_search(
    pool: &PgPool,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
    page: &u64,
) -> Result<Vec<Domain>, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;

    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Pull the Domains
    let domains = domain_select_search(&mut tx, domain_name, owner, extra, &PAGE_SIZE, &offset)
        .await
        .map_err(InternalServerError)?;

    //TODO add support if more fields present

    Ok(domains)
}

/// Edit a Domain
pub async fn domain_edit(
    pool: &PgPool,
    domain_name: &str,
    domain_param: &DomainParam,
    username: &str,
) -> Result<Domain, poem::Error> {
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
    let domain = domain_select(&mut tx, &domain_param.domain)
        .await
        .map_err(InternalServerError)?;

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(domain)
}

/// Remove a Domain
pub async fn domain_remove(pool: &PgPool, domain_name: &str) -> Result<Domain, poem::Error> {
    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Check to make sure domain already exists
    let domain = domain_select(&mut tx, domain_name)
        .await
        .map_err(NotFound)?;

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
