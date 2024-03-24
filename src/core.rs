use crate::db::{domain_count, domain_insert, domain_select};
use chrono::{DateTime, Utc};
use poem::{error::InternalServerError, http::StatusCode};
use poem_openapi::Object;
use serde_json::Value;
use sqlx::PgPool;

/// Shared Domain struct
#[derive(Object)]
pub struct Domain {
    pub id: i32,
    pub domain: String,
    pub extra: Value,
    pub created_by: String,
    pub created_date: DateTime<Utc>,
    pub modified_by: String,
    pub modified_date: DateTime<Utc>,
}

pub async fn domain_add(
    pool: &PgPool,
    domain_name: &String,
    extra: &Value,
    username: &String,
) -> Result<Domain, poem::Error> {
    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Check if domain already exists
    let count = domain_count(&mut tx, domain_name)
        .await
        .map_err(InternalServerError)?;
    if count >= 1 {
        return Err(poem::Error::from_status(StatusCode::CONFLICT));
    }

    // Add new domain
    domain_insert(&mut tx, domain_name, extra, username)
        .await
        .map_err(InternalServerError)?;

    // Pull value
    let domain = domain_select(&mut tx, domain_name)
        .await
        .map_err(InternalServerError)?;

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(domain)
}
