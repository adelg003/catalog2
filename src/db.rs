use crate::core::Domain;
use chrono::Utc;
use serde_json::Value;
use sqlx::{query, query_as, Postgres, Transaction};

/// Struct for counting rows returned
struct Counter {
    count: Option<i64>,
}

/// Add a domain to the domain table
pub async fn domain_insert(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &String,
    extra: &Value,
    user: &String,
) -> Result<u64, sqlx::Error> {
    let rows_affected = query!(
        "INSERT INTO domain (
            domain,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date
        ) VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6
        )",
        domain_name,
        extra,
        user,
        Utc::now(),
        user,
        Utc::now(),
    )
    .execute(&mut **tx)
    .await?
    .rows_affected();

    Ok(rows_affected)
}

pub async fn domain_select(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &String,
) -> Result<Domain, sqlx::Error> {
    let domain = query_as!(
        Domain,
        "SELECT
            id,
            domain,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date
        FROM
            domain
        WHERE
            domain = $1",
        domain_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(domain)
}

pub async fn domain_count(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &String,
) -> Result<i64, sqlx::Error> {
    let counter = query_as!(
        Counter,
        "SELECT
            COUNT(*) as count
        FROM
            domain
        WHERE
            domain = $1",
        domain_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    let count = counter.count.unwrap_or(0);

    Ok(count)
}
