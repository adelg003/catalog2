use crate::core::{DomainParam, ModelParam};
use chrono::{DateTime, Utc};
use sqlx::{prelude::FromRow, query, query_as, Postgres, QueryBuilder, Transaction};

/// Row from the Domain table
#[derive(FromRow)]
pub struct DomainRow {
    pub id: i32,
    pub domain: String,
    pub owner: String,
    pub extra: serde_json::Value,
    pub created_by: String,
    pub created_date: DateTime<Utc>,
    pub modified_by: String,
    pub modified_date: DateTime<Utc>,
}

#[derive(FromRow)]
pub struct ModelRow {
    pub id: i32,
    pub model: String,
    pub domain_id: i32,
    pub domain: String,
    pub owner: String,
    pub extra: serde_json::Value,
    pub created_by: String,
    pub created_date: DateTime<Utc>,
    pub modified_by: String,
    pub modified_date: DateTime<Utc>,
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
    let domain_row = query_as!(
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

    Ok(domain_row)
}

/// Pull multiple domains is the match the criteria
pub async fn domain_select_search(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
    limit: &Option<u64>,
    offset: &Option<u64>,
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

    // Add ORDER BY
    query.push(" ORDER BY id ");

    // Add LIMIT
    if let Some(limit) = limit {
        query.push(format!(" LIMIT {} ", limit));

        // Add OFFSET
        if let Some(offset) = offset {
            query.push(format!(" OFFSET {} ", offset));
        }
    }

    // Run our generated SQL statement
    let domain_rows = query
        .build_query_as::<DomainRow>()
        .fetch_all(&mut **tx)
        .await?;

    Ok(domain_rows)
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

/// Add a model to the model table
pub async fn model_insert(
    tx: &mut Transaction<'_, Postgres>,
    model_param: &ModelParam,
    domain_id: &i32,
    username: &str,
) -> Result<u64, sqlx::Error> {
    let rows_affected = query!(
        "INSERT INTO model (
            model,
            domain_id,
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
            $7,
            $8
        )",
        model_param.model,
        domain_id,
        model_param.owner,
        model_param.extra,
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
/// Pull one model
pub async fn model_select(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<ModelRow, sqlx::Error> {
    let model_row = query_as!(
        ModelRow,
        "SELECT
            model.id,
            model.model,
            model.domain_id,
            domain.domain,
            model.owner,
            model.extra,
            model.created_by,
            model.created_date,
            model.modified_by,
            model.modified_date
        FROM
            model
        LEFT JOIN
            domain
        on
            model.domain_id = domain.id 
        WHERE
            model = $1",
        model_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(model_row)
}
