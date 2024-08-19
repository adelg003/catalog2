use crate::{
    field::{DbxDataType, Field},
    model::Model,
    schema::core::{Schema, SchemaParam, SearchSchemaParam},
};
use chrono::Utc;
use sqlx::{query, query_as, Postgres, QueryBuilder, Transaction};

/// Add a schema to the modeschemale
pub async fn schema_insert(
    tx: &mut Transaction<'_, Postgres>,
    schema_param: &SchemaParam,
    username: &str,
) -> Result<Schema, sqlx::Error> {
    query_as!(
        Schema,
        "INSERT INTO schema (
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
        schema_param.name,
        schema_param.owner,
        schema_param.extra,
        username,
        Utc::now(),
        username,
        Utc::now(),
    )
    .fetch_one(&mut **tx)
    .await?;

    // Pull the row
    let schema = schema_select(tx, &schema_param.name).await?;

    Ok(schema)
}

/// Pull one schema
pub async fn schema_select(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
) -> Result<Schema, sqlx::Error> {
    let schema = query_as!(
        Schema,
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
            schema
        WHERE
            name = $1",
        schema_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(schema)
}

/// Update a schema
pub async fn schema_update(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
    schema_param: &SchemaParam,
    username: &str,
) -> Result<Schema, sqlx::Error> {
    let schema = query_as!(
        Schema,
        "UPDATE
            schema
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
        schema_param.name,
        schema_param.owner,
        schema_param.extra,
        username,
        Utc::now(),
        schema_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(schema)
}

/// Delete a schema
pub async fn schema_drop(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
) -> Result<Schema, sqlx::Error> {
    let schema = query_as!(
        Schema,
        "DELETE FROM
            schema
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
        schema_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(schema)
}

/// Pull many fields by schema
pub async fn field_select_by_schema(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
) -> Result<Vec<Field>, sqlx::Error> {
    let fields = query_as!(
        Field,
        "SELECT
            field.id,
            field.name,
            field.schema_id,
            schema.name AS \"schema_name\",
            ROW_NUMBER() OVER (ORDER BY field.id) as \"seq\",
            field.is_primary,
            field.data_type AS \"data_type!: DbxDataType\",
            field.is_nullable,
            field.precision,
            field.scale,
            field.extra,
            field.created_by,
            field.created_date,
            field.modified_by,
            field.modified_date
        FROM
            field
        LEFT JOIN
            schema
        ON
            field.schema_id = schema.id
        WHERE
            schema.name = $1
        ORDER BY
            field.id",
        schema_name,
    )
    .fetch_all(&mut **tx)
    .await?;

    Ok(fields)
}

/// Delete all field for a schema
pub async fn field_drop_by_schema(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
) -> Result<Vec<Field>, sqlx::Error> {
    // Pull the rows and parent
    let schema = schema_select(tx, schema_name).await?;
    let fields = field_select_by_schema(tx, schema_name).await?;

    // Now run the delete since we have the rows in memory
    query!(
        "DELETE FROM
            field
        WHERE
            schema_id = $1",
        schema.id,
    )
    .execute(&mut **tx)
    .await?;

    Ok(fields)
}

/// Pull many models by schema
pub async fn model_select_by_schema(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
) -> Result<Vec<Model>, sqlx::Error> {
    let models = query_as!(
        Model,
        "SELECT
            model.id,
            model.name,
            model.domain_id,
            domain.name AS \"domain_name\",
            model.schema_id,
            schema.name AS \"schema_name\",
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
        ON
            model.domain_id = domain.id
        LEFT JOIN
            schema
        ON
            model.schema_id = schema.id
        WHERE
            schema.name = $1
        ORDER BY
            model.id",
        schema_name,
    )
    .fetch_all(&mut **tx)
    .await?;

    Ok(models)
}

/// Pull multiple schemas that match the criteria
pub async fn search_schema_select(
    tx: &mut Transaction<'_, Postgres>,
    search_param: &SearchSchemaParam,
    limit: &Option<u64>,
    offset: &Option<u64>,
) -> Result<Vec<Schema>, sqlx::Error> {
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
            schema",
    );

    // Should we add a WHERE statement?
    if search_param.schema_name.is_some()
        || search_param.owner.is_some()
        || search_param.extra.is_some()
    {
        query.push(" WHERE ");

        // Start building the WHERE statement with the "AND" separating the condition.
        let mut separated = query.separated(" AND ");

        // Fuzzy search
        if let Some(model_name) = &search_param.schema_name {
            separated.push(format!("name ILIKE '%{model_name}%'"));
        }
        if let Some(owner) = &search_param.owner {
            separated.push(format!("owner ILIKE '%{owner}%'"));
        }
        if let Some(extra) = &search_param.extra {
            separated.push(format!("extra::text ILIKE '%{extra}%'"));
        }
    }

    // Add ORDER BY
    query.push(" ORDER BY id ");

    // Add LIMIT
    if let Some(limit) = limit {
        query.push(format!(" LIMIT {limit} "));

        // Add OFFSET
        if let Some(offset) = offset {
            query.push(format!(" OFFSET {offset} "));
        }
    }

    // Run our generated SQL statement
    let schema = query
        .build_query_as::<Schema>()
        .fetch_all(&mut **tx)
        .await?;

    Ok(schema)
}
