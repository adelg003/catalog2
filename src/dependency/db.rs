use crate::{
    dependency::core::{Dependency, DependencyParam, DependencyParamUpdate, DependencyType},
    model::model_select,
    pack::pack_select,
};
use chrono::Utc;
use sqlx::{query, query_as, Postgres, Transaction};

/// Add a dependency to a model or pack
pub async fn dependency_insert(
    tx: &mut Transaction<'_, Postgres>,
    dependency_type: &DependencyType,
    param: &DependencyParam,
    username: &str,
) -> Result<Dependency, sqlx::Error> {
    // Make sure related records exists
    let model = model_select(tx, &param.model_name).await?;
    let pack = pack_select(tx, &param.pack_name).await?;

    // Change query per dependency_type
    match dependency_type {
        DependencyType::Model => {
            query!(
                "INSERT INTO model_dependency (
                    model_id,
                    pack_id,
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
                model.id,
                pack.id,
                param.extra,
                username,
                Utc::now(),
                username,
                Utc::now(),
            )
            .execute(&mut **tx)
            .await?
        }
        DependencyType::Pack => {
            query!(
                "INSERT INTO pack_dependency (
                    pack_id,
                    model_id,
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
                pack.id,
                model.id,
                param.extra,
                username,
                Utc::now(),
                username,
                Utc::now(),
            )
            .execute(&mut **tx)
            .await?
        }
    };

    // Pull the row
    let dependency =
        dependency_select(tx, dependency_type, &param.model_name, &param.pack_name).await?;

    Ok(dependency)
}

/// Pull one dependency for a model or pack
pub async fn dependency_select(
    tx: &mut Transaction<'_, Postgres>,
    dependency_type: &DependencyType,
    model_name: &str,
    pack_name: &str,
) -> Result<Dependency, sqlx::Error> {
    // Change query per dependency_type
    let dependency = match dependency_type {
        DependencyType::Model => {
            query_as!(
                Dependency,
                "SELECT
                    dependency.id,
                    dependency.model_id,
                    model.name AS model_name,
                    dependency.pack_id,
                    pack.name AS pack_name,
                    dependency.extra,
                    dependency.created_by,
                    dependency.created_date,
                    dependency.modified_by,
                    dependency.modified_date
                FROM
                    model_dependency AS dependency
                INNER JOIN
                    model
                ON
                    dependency.model_id = model.id
                INNER JOIN
                    pack
                ON
                    dependency.pack_id = pack.id
                WHERE
                    model.name = $1
                    AND pack.name = $2",
                model_name,
                pack_name,
            )
            .fetch_one(&mut **tx)
            .await?
        }
        DependencyType::Pack => {
            query_as!(
                Dependency,
                "SELECT
                    dependency.id,
                    dependency.model_id,
                    model.name AS model_name,
                    dependency.pack_id,
                    pack.name AS pack_name,
                    dependency.extra,
                    dependency.created_by,
                    dependency.created_date,
                    dependency.modified_by,
                    dependency.modified_date
                FROM
                    pack_dependency AS dependency
                INNER JOIN
                    model
                ON
                    dependency.model_id = model.id
                INNER JOIN
                    pack
                ON
                    dependency.pack_id = pack.id
                WHERE
                    model.name = $1
                    AND pack.name = $2",
                model_name,
                pack_name,
            )
            .fetch_one(&mut **tx)
            .await?
        }
    };

    Ok(dependency)
}

/// Pull all model dependencies for a single model or pack.
pub async fn dependencies_select(
    tx: &mut Transaction<'_, Postgres>,
    dependency_type: &DependencyType,
    name: &str,
) -> Result<Vec<Dependency>, sqlx::Error> {
    // Change query per dependency_type
    let dependencies = match dependency_type {
        DependencyType::Model => {
            query_as!(
                Dependency,
                "SELECT
                    dependency.id,
                    dependency.model_id,
                    model.name AS model_name,
                    dependency.pack_id,
                    pack.name AS pack_name,
                    dependency.extra,
                    dependency.created_by,
                    dependency.created_date,
                    dependency.modified_by,
                    dependency.modified_date
                FROM
                    model_dependency AS dependency
                INNER JOIN
                    model
                ON
                    dependency.model_id = model.id
                INNER JOIN
                    pack
                ON
                    dependency.pack_id = pack.id
                WHERE
                    model.name = $1",
                name,
            )
            .fetch_all(&mut **tx)
            .await?
        }
        DependencyType::Pack => {
            query_as!(
                Dependency,
                "SELECT
                    dependency.id,
                    dependency.model_id,
                    model.name AS model_name,
                    dependency.pack_id,
                    pack.name AS pack_name,
                    dependency.extra,
                    dependency.created_by,
                    dependency.created_date,
                    dependency.modified_by,
                    dependency.modified_date
                FROM
                    pack_dependency AS dependency
                INNER JOIN
                    model
                ON
                    dependency.model_id = model.id
                INNER JOIN
                    pack
                ON
                    dependency.pack_id = pack.id
                WHERE
                    pack.name = $1",
                name,
            )
            .fetch_all(&mut **tx)
            .await?
        }
    };

    Ok(dependencies)
}

/// Update a model or pack dependency
pub async fn dependency_update(
    tx: &mut Transaction<'_, Postgres>,
    dependency_type: &DependencyType,
    model_name: &str,
    pack_name: &str,
    param: &DependencyParamUpdate,
    username: &str,
) -> Result<Dependency, sqlx::Error> {
    // Change query per dependency_type
    let rows_affected = match dependency_type {
        DependencyType::Model => query!(
            "UPDATE
                model_dependency AS dependency
            SET 
                extra = $1,
                modified_by = $2,
                modified_date = $3
            FROM
                model,
                pack
            WHERE
                dependency.model_id = model.id
                AND dependency.pack_id = pack.id
                AND model.name = $4
                AND pack.name = $5",
            param.extra,
            username,
            Utc::now(),
            model_name,
            pack_name,
        )
        .execute(&mut **tx)
        .await?
        .rows_affected(),
        DependencyType::Pack => query!(
            "UPDATE
                pack_dependency AS dependency
            SET 
                extra = $1,
                modified_by = $2,
                modified_date = $3
            FROM
                model,
                pack
            WHERE
                dependency.model_id = model.id
                AND dependency.pack_id = pack.id
                AND model.name = $4
                AND pack.name = $5",
            param.extra,
            username,
            Utc::now(),
            model_name,
            pack_name,
        )
        .execute(&mut **tx)
        .await?
        .rows_affected(),
    };

    // Check if any rows were updated.
    if rows_affected == 0 {
        return Err(sqlx::Error::RowNotFound);
    }

    // Pull the row, but with the domain name added
    let dependency = dependency_select(tx, dependency_type, model_name, pack_name).await?;

    Ok(dependency)
}

/// Delete a model or pack dependency
pub async fn dependency_drop(
    tx: &mut Transaction<'_, Postgres>,
    dependency_type: &DependencyType,
    model_name: &str,
    pack_name: &str,
) -> Result<Dependency, sqlx::Error> {
    // Pull the row and make sure it exists
    let dependency = dependency_select(tx, dependency_type, model_name, pack_name).await?;

    // Now run the delete since we have the row in memory
    // Change query per dependency_type
    match dependency_type {
        DependencyType::Model => {
            query!(
                "DELETE FROM
                    model_dependency AS dependency
                USING
                    model,
                    pack
                WHERE
                    dependency.model_id = model.id
                    AND dependency.pack_id = pack.id
                    AND model.name = $1
                    AND pack.name = $2",
                model_name,
                pack_name,
            )
            .execute(&mut **tx)
            .await?
        }
        DependencyType::Pack => {
            query!(
                "DELETE FROM
                    pack_dependency AS dependency
                USING
                    model,
                    pack
                WHERE
                    dependency.model_id = model.id
                    AND dependency.pack_id = pack.id
                    AND model.name = $1
                    AND pack.name = $2",
                model_name,
                pack_name,
            )
            .execute(&mut **tx)
            .await?
        }
    };

    Ok(dependency)
}

/// Delete all dependencies for a model or pack
pub async fn dependencies_drop(
    tx: &mut Transaction<'_, Postgres>,
    dependency_type: &DependencyType,
    name: &str,
) -> Result<Vec<Dependency>, sqlx::Error> {
    // Pull the rows. If not exists, return empty Vector
    let dependencies = dependencies_select(tx, dependency_type, name).await?;

    // Now run the delete since we have the row in memory
    match dependency_type {
        DependencyType::Model => {
            query!(
                "DELETE FROM
                    model_dependency AS dependency
                USING
                    model
                WHERE
                    dependency.model_id = model.id
                    AND model.name = $1",
                name,
            )
            .execute(&mut **tx)
            .await?
        }
        DependencyType::Pack => {
            query!(
                "DELETE FROM
                    pack_dependency AS dependency
                USING
                    pack
                WHERE
                    dependency.pack_id = pack.id
                    AND pack.name = $1",
                name,
            )
            .execute(&mut **tx)
            .await?
        }
    };

    Ok(dependencies)
}
