use crate::core::Domain;
use chrono::Utc;
use serde_json::Value;
use sqlx::{query, query_as, Postgres, QueryBuilder, Transaction};

/// Struct for counting rows returned
struct Counter {
    count: Option<i64>,
}

/// Add a domain to the domain table
pub async fn domain_insert(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &String,
    owner: &String,
    extra: &Value,
    user: &String,
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
        domain_name,
        owner,
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

/// Pull one domain
pub async fn domain_select(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &String,
) -> Result<Domain, sqlx::Error> {
    let domain = query_as!(
        Domain,
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
) -> Result<Vec<Domain>, sqlx::Error> {
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
        .build_query_as::<Domain>()
        .fetch_all(&mut **tx)
        .await?;

    Ok(domains)
}

/// How many domain exists with a given name
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
