use chrono::{DateTime, Utc};
use poem::error::InternalServerError;
use poem_openapi::Object;
use regex::Regex;
use sqlx::{query, query_as, FromRow, Postgres, QueryBuilder, Transaction};
use validator::{Validate, ValidationError};

/// Domain Shared
#[derive(FromRow, Object)]
pub struct Domain {
    id: i32,
    name: String,
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
    ) -> Result<DomainModels, poem::Error> {
        // Pull models
        let models = model_select_many(tx, &self.name)
            .await
            .map_err(InternalServerError)?;

        Ok(DomainModels {
            domain: self,
            models,
        })
    }
}

/// How to create a new domain
#[derive(Object, Validate)]
pub struct DomainParam {
    name: String,
    #[validate(email)]
    owner: String,
    extra: serde_json::Value,
}

/// Model to return via the API
#[derive(FromRow, Object)]
pub struct Model {
    id: i32,
    name: String,
    domain_id: i32,
    domain_name: String,
    owner: String,
    extra: serde_json::Value,
    created_by: String,
    created_date: DateTime<Utc>,
    modified_by: String,
    modified_date: DateTime<Utc>,
}

/// How to create a new model
#[derive(Object, Validate)]
pub struct ModelParam {
    #[validate(custom(function = dbx_validater))]
    name: String,
    domain_name: String,
    #[validate(email)]
    owner: String,
    extra: serde_json::Value,
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

/// Domain with models
#[derive(Object)]
pub struct DomainModels {
    domain: Domain,
    models: Vec<Model>,
}

//TODO ModelFields

/// Add a domain to the domain table
pub async fn domain_insert(
    tx: &mut Transaction<'_, Postgres>,
    domain_param: &DomainParam,
    username: &str,
) -> Result<Domain, sqlx::Error> {
    let domain = query_as!(
        Domain,
        "INSERT INTO domain (
            name,
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
        ) RETURNING
            id,
            name,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date",
        domain_param.name,
        domain_param.owner,
        domain_param.extra,
        username,
        Utc::now(),
        username,
        Utc::now(),
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(domain)
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
            name,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date
        FROM
            domain
        WHERE
            name = $1",
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
            name,
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
            separated.push(format!("name LIKE '%{}%'", domain_name));
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
) -> Result<Domain, sqlx::Error> {
    let domain = query_as!(
        Domain,
        "UPDATE
            domain
        SET 
            name = $1,
            owner = $2,
            extra = $3,
            modified_by = $4,
            modified_date = $5
        WHERE
            name = $6
        RETURNING
            id,
            name,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date",
        domain_param.name,
        domain_param.owner,
        domain_param.extra,
        username,
        Utc::now(),
        domain_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(domain)
}

/// Delete a domain
pub async fn domain_drop(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<Domain, sqlx::Error> {
    let domain = query_as!(
        Domain,
        "DELETE FROM
            domain
        WHERE
            name = $1
        RETURNING
            id,
            name,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date",
        domain_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(domain)
}

/// Add a model to the model table
pub async fn model_insert(
    tx: &mut Transaction<'_, Postgres>,
    model_param: &ModelParam,
    username: &str,
) -> Result<Model, sqlx::Error> {
    let domain = domain_select(tx, &model_param.domain_name).await?;

    query!(
        "INSERT INTO model (
            name,
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
        model_param.name,
        domain.id,
        model_param.owner,
        model_param.extra,
        username,
        Utc::now(),
        username,
        Utc::now(),
    )
    .execute(&mut **tx)
    .await?;

    // Pull the row
    let model = model_select(tx, &model_param.name).await?;

    Ok(model)
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
            model.name,
            model.domain_id,
            domain.name AS \"domain_name\",
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
            model.name = $1",
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
            model.name,
            model.domain_id,
            domain.name AS \"domain_name\",
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
            domain.name = $1",
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
            model.name,
            model.domain_id,
            domain.name AS \"domain_name\",
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
    username: &str,
) -> Result<Model, sqlx::Error> {
    let domain = domain_select(tx, &model_param.domain_name).await?;

    let rows_affected = query!(
        "UPDATE
            model
        SET 
            name = $1,
            domain_id = $2,
            owner = $3,
            extra = $4,
            modified_by = $5,
            modified_date = $6
        WHERE
            name = $7",
        model_param.name,
        domain.id,
        model_param.owner,
        model_param.extra,
        username,
        Utc::now(),
        model_name,
    )
    .execute(&mut **tx)
    .await?
    .rows_affected();

    // Check if any rows were updated.
    if rows_affected == 0 {
        return Err(sqlx::Error::RowNotFound);
    }

    // Pull the row, but with the domain name added
    let model = model_select(tx, &model_param.name).await?;

    Ok(model)
}

/// Delete a model
pub async fn model_drop(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Model, sqlx::Error> {
    // Pull the row
    let model = model_select(tx, model_name).await?;

    // Now run the delete since we have the row in memory
    query!(
        "DELETE FROM
            model
        WHERE
            name = $1",
        model_name,
    )
    .execute(&mut **tx)
    .await?;

    Ok(model)
}

//TODO Add Unit Test
