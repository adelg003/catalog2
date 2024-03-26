use crate::core::DomainParam;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{prelude::FromRow, query, query_as, Postgres, QueryBuilder, Transaction};

/// Row from the Domain table
#[derive(FromRow)]
pub struct DomainRow {
    pub id: i32,
    pub domain: String,
    pub owner: String,
    pub extra: Value,
    pub created_by: String,
    pub created_date: DateTime<Utc>,
    pub modified_by: String,
    pub modified_date: DateTime<Utc>,
}

/// Struct for counting rows returned
struct Counter {
    count: Option<i64>,
}

/// Add a domain to the domain table
pub async fn domain_insert(
    tx: &mut Transaction<'_, Postgres>,
    domain_param: &DomainParam,
    username: &str,
) -> Result<u64, sqlx::Error> {
    let rows_affected = query!(
        "INSERT INTO domain (
            domain,
            owner,
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
            $6,
            $7
        )",
        domain_param.domain,
        domain_param.owner,
        domain_param.extra,
        username,
        Utc::now(),
        username,
        Utc::now(),
    )
    .execute(&mut **tx)
    .await?
    .rows_affected();

    Ok(rows_affected)
}

/// Pull one domain
pub async fn domain_select(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<DomainRow, sqlx::Error> {
    let domain = query_as!(
        DomainRow,
        "SELECT
            id,
            domain,
            owner,
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

/// Pull multiple domains is the match the criteria
pub async fn domain_select_search(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
    limit: &u64,
    offset: &u64,
) -> Result<Vec<DomainRow>, sqlx::Error> {
    // Query we will be modifying
    let mut query = QueryBuilder::<'_, Postgres>::new(
        "SELECT
            id,
            domain,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date
        FROM
            domain",
    );

    // Should we add a WHERE statement?
    if domain_name.is_some() || owner.is_some() || extra.is_some() {
        query.push(" WHERE ");

        // Start building the WHERE statement with the "AND" separating the condition.
        let mut separated = query.separated(" AND ");

        // Fuzzy search for domain
        if let Some(domain_name) = domain_name {
            separated.push(format!("domain LIKE '%{}%'", domain_name));
        }

        // Fuzzy search for owner
        if let Some(owner) = owner {
            separated.push(format!("owner LIKE '%{}%'", owner));
        }

        // Fuzzy search for extra
        if let Some(extra) = extra {
            separated.push(format!("extra::text LIKE '%{}%'", extra));
        }
    }

    // Add ORDER, LIMIT, and OFFSET to our SQL statement
    query.push(format!(" ORDER BY id LIMIT {} OFFSET {}", limit, offset));

    // Run our generated SQL statement
    let domains = query
        .build_query_as::<DomainRow>()
        .fetch_all(&mut **tx)
        .await?;

    Ok(domains)
}

/// How many domain exists with a given name
pub async fn domain_count(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
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

/// Update a domain
pub async fn domain_update(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
    domain_param: &DomainParam,
    username: &str,
) -> Result<u64, sqlx::Error> {
    let rows_affected = query!(
        "UPDATE
            domain
        SET 
            domain = $1,
            owner = $2,
            extra = $3,
            modified_by = $4,
            modified_date = $5
        WHERE
            domain = $6",
        domain_param.domain,
        domain_param.owner,
        domain_param.extra,
        username,
        Utc::now(),
        domain_name,
    )
    .execute(&mut **tx)
    .await?
    .rows_affected();

    Ok(rows_affected)
}

/// Delete a domain
pub async fn domain_drop(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<u64, sqlx::Error> {
    let rows_affected = query!(
        "DELETE FROM
            domain
        WHERE
            domain = $1",
        domain_name,
    )
    .execute(&mut **tx)
    .await?
    .rows_affected();

    Ok(rows_affected)
}
