use crate::core::{DomainModel, DomainParam, ModelParam};
use chrono::{DateTime, Utc};
use poem::error::InternalServerError;
use poem_openapi::Object;
use sqlx::{query, query_as, FromRow, Postgres, QueryBuilder, Transaction};

/// Domain Shared
#[derive(FromRow, Object)]
pub struct Domain {
    pub id: i32,
    domain: String,
    owner: String,
    extra: serde_json::Value,
    created_by: String,
    created_date: DateTime<Utc>,
    modified_by: String,
    modified_date: DateTime<Utc>,
}

impl Domain {
    /// Add model details to a domain
    pub async fn add_models(
        self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<DomainModel, poem::Error> {
        // Pull models
        let models = model_select_many(tx, &self.domain)
            .await
            .map_err(InternalServerError)?;

        Ok(DomainModel {
            domain: self,
            models,
        })
    }
}

/// Model to return via the API
#[derive(FromRow, Object)]
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

/// Pull multiple domains that match the criteria
pub async fn domain_select_search(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
    limit: &Option<u64>,
    offset: &Option<u64>,
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

        // Fuzzy search
        if let Some(domain_name) = domain_name {
            separated.push(format!("domain LIKE '%{}%'", domain_name));
        }
        if let Some(owner) = owner {
            separated.push(format!("owner LIKE '%{}%'", owner));
        }
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
    let domain = query
        .build_query_as::<Domain>()
        .fetch_all(&mut **tx)
        .await?;

    Ok(domain)
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
) -> Result<Model, sqlx::Error> {
    let model = query_as!(
        Model,
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

    Ok(model)
}

/// Pull many models by domain
async fn model_select_many(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<Vec<Model>, sqlx::Error> {
    let model = query_as!(
        Model,
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
            domain.domain = $1",
        domain_name,
    )
    .fetch_all(&mut **tx)
    .await?;

    Ok(model)
}

/// Pull multiple models that match the criteria
pub async fn model_select_search(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &Option<String>,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
    limit: &Option<u64>,
    offset: &Option<u64>,
) -> Result<Vec<Model>, sqlx::Error> {
    // Query we will be modifying
    let mut query = QueryBuilder::<'_, Postgres>::new(
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
            model.domain_id = domain.id",
    );

    // Should we add a WHERE statement?
    if model_name.is_some() || domain_name.is_some() || owner.is_some() || extra.is_some() {
        query.push(" WHERE ");

        // Start building the WHERE statement with the "AND" separating the condition.
        let mut separated = query.separated(" AND ");

        // Fuzzy search
        if let Some(model_name) = model_name {
            separated.push(format!("model.model LIKE '%{}%'", model_name));
        }
        if let Some(domain_name) = domain_name {
            separated.push(format!("domain.domain LIKE '%{}%'", domain_name));
        }
        if let Some(owner) = owner {
            separated.push(format!("model.owner LIKE '%{}%'", owner));
        }
        if let Some(extra) = extra {
            separated.push(format!("model.extra::text LIKE '%{}%'", extra));
        }
    }

    // Add ORDER BY
    query.push(" ORDER BY model.id ");

    // Add LIMIT
    if let Some(limit) = limit {
        query.push(format!(" LIMIT {} ", limit));

        // Add OFFSET
        if let Some(offset) = offset {
            query.push(format!(" OFFSET {} ", offset));
        }
    }

    // Run our generated SQL statement
    let model = query.build_query_as::<Model>().fetch_all(&mut **tx).await?;

    Ok(model)
}

/// Update a model
pub async fn model_update(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    model_param: &ModelParam,
    domain_id: &i32,
    username: &str,
) -> Result<u64, sqlx::Error> {
    let rows_affected = query!(
        "UPDATE
            model
        SET 
            model = $1,
            domain_id = $2,
            owner = $3,
            extra = $4,
            modified_by = $5,
            modified_date = $6
        WHERE
            model = $7",
        model_param.model,
        domain_id,
        model_param.owner,
        model_param.extra,
        username,
        Utc::now(),
        model_name,
    )
    .execute(&mut **tx)
    .await?
    .rows_affected();

    Ok(rows_affected)
}

/// Delete a model
pub async fn model_drop(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<u64, sqlx::Error> {
    let rows_affected = query!(
        "DELETE FROM
            model
        WHERE
            model = $1",
        model_name,
    )
    .execute(&mut **tx)
    .await?
    .rows_affected();

    Ok(rows_affected)
}
//TODO Add Unit Test
