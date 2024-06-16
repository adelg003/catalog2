use crate::{
    domain::domain_select,
    field::{DbxDataType, Field},
    model::core::{Model, ModelParam, },
};
use chrono::Utc;
use sqlx::{query, query_as, Postgres, QueryBuilder, Transaction};

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
        ON
            model.domain_id = domain.id 
        WHERE
            model.name = $1",
        model_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(model)
}


/// Update a model
pub async fn model_update(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    model_param: &ModelParam,
    username: &str,
) -> Result<Model, sqlx::Error> {
    // Make sure related domain exists
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

/// Pull many fields by model
pub async fn field_select_by_model(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Vec<Field>, sqlx::Error> {
    let fields = query_as!(
        Field,
        "SELECT
            field.id,
            field.name,
            field.model_id,
            model.name AS \"model_name\",
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
            model
        ON
            field.model_id = model.id 
        WHERE
            model.name = $1
        ORDER BY
            field.id",
        model_name,
    )
    .fetch_all(&mut **tx)
    .await?;

    Ok(fields)
}

/// Delete all field for a model
pub async fn field_drop_by_model(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Vec<Field>, sqlx::Error> {
    // Pull the rows and parent
    let model = model_select(tx, model_name).await?;
    let fields = field_select_by_model(tx, model_name).await?;

    // Now run the delete since we have the rows in memory
    query!(
        "DELETE FROM
            field
        WHERE
            model_id = $1",
        model.id,
    )
    .execute(&mut **tx)
    .await?;

    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::util::test_utils::gen_test_model_param,
        util::test_utils::{
            gen_test_domain_json, gen_test_field_json, post_test_domain, post_test_field,
        },
    };
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use sqlx::PgPool;

    /// Test create model
    #[sqlx::test]
    async fn test_model_insert(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let model = {
            let model_param = gen_test_model_param("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();

            let model = model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();

            model
        };

        assert_eq!(model.id, 1);
        assert_eq!(model.name, "test_model");
        assert_eq!(model.domain_id, 1);
        assert_eq!(model.domain_name, "test_domain");
        assert_eq!(model.owner, "test_model@test.com");
        assert_eq!(
            model.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(model.created_by, "test");
        assert_eq!(model.modified_by, "test");
    }

    /// Test model insert where no domain found
    #[sqlx::test]
    async fn test_model_insert_not_found(pool: PgPool) {
        let err = {
            let model_param = gen_test_model_param("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_insert(&mut tx, &model_param, "test")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test double model create conflict
    #[sqlx::test]
    async fn test_model_insert_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let model_param = gen_test_model_param("test_model", "test_domain");

        {
            let mut tx = pool.begin().await.unwrap();
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_insert(&mut tx, &model_param, "test")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "duplicate key value violates unique constraint \"model_name_key\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test model select
    #[sqlx::test]
    async fn test_model_select(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_param("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let model = {
            let mut tx = pool.begin().await.unwrap();
            model_select(&mut tx, "test_model").await.unwrap()
        };

        assert_eq!(model.id, 1);
        assert_eq!(model.name, "test_model");
        assert_eq!(model.domain_id, 1);
        assert_eq!(model.domain_name, "test_domain");
        assert_eq!(model.owner, "test_model@test.com");
        assert_eq!(
            model.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(model.created_by, "test");
        assert_eq!(model.modified_by, "test");
    }

    /// Test Reading a model that does not exists
    #[sqlx::test]
    async fn test_model_select_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_select(&mut tx, "test_model").await.unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }


    /// Test model update
    #[sqlx::test]
    async fn test_model_update(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_param("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let model = {
            let model_param = gen_test_model_param("foobar_model", "foobar_domain");

            let mut tx = pool.begin().await.unwrap();
            model_update(&mut tx, "test_model", &model_param, "foobar")
                .await
                .unwrap()
        };

        assert_eq!(model.id, 1);
        assert_eq!(model.name, "foobar_model");
        assert_eq!(model.domain_id, 2);
        assert_eq!(model.domain_name, "foobar_domain");
        assert_eq!(model.owner, "foobar_model@test.com");
        assert_eq!(
            model.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(model.created_by, "test");
        assert_eq!(model.modified_by, "foobar");
    }

    /// Test model update where no domain or model found
    #[sqlx::test]
    async fn test_model_update_not_found(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let err = {
            let model_param = gen_test_model_param("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_update(&mut tx, "test_model", &model_param, "test")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };

        {
            let model_param = gen_test_model_param("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let model_param = gen_test_model_param("test_model", "foobar_domain");

            let mut tx = pool.begin().await.unwrap();
            model_update(&mut tx, "test_model", &model_param, "foobar")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test model update with conflict
    #[sqlx::test]
    async fn test_model_update_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_param("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let model_param = gen_test_model_param("foobar_model", "test_domain");
            model_insert(&mut tx, &model_param, "foobar").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let model_param = gen_test_model_param("foobar_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_update(&mut tx, "test_model", &model_param, "foobar")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "duplicate key value violates unique constraint \"model_name_key\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test model drop
    #[sqlx::test]
    async fn test_model_drop(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_param("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let model = {
            let mut tx = pool.begin().await.unwrap();
            let model = model_drop(&mut tx, "test_model").await.unwrap();

            tx.commit().await.unwrap();

            model
        };

        assert_eq!(model.id, 1);
        assert_eq!(model.name, "test_model");
        assert_eq!(model.domain_id, 1);
        assert_eq!(model.domain_name, "test_domain");
        assert_eq!(model.owner, "test_model@test.com");
        assert_eq!(
            model.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(model.created_by, "test");
        assert_eq!(model.modified_by, "test");

        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_select(&mut tx, "test_domain").await.unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test model drop if not exists
    #[sqlx::test]
    async fn test_model_drop_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_drop(&mut tx, "test_model").await.unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test model drop if children not droppped
    #[sqlx::test]
    async fn test_model_drop_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_param("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let body = gen_test_field_json("test_field", "test_model");
        post_test_field(&body, &pool).await;

        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_drop(&mut tx, "test_model").await.unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "update or delete on table \"model\" violates foreign key constraint \"field_model_id_fkey\" on table \"field\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test field select by model
    #[sqlx::test]
    async fn test_field_select_by_model(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();
            let fields = field_select_by_model(&mut tx, "test_model").await.unwrap();

            assert_eq!(fields.len(), 0);
        }

        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_param("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        // Select Model with Fields
        {
            let mut tx = pool.begin().await.unwrap();

            let fields = field_select_by_model(&mut tx, "test_model").await.unwrap();

            assert_eq!(fields.len(), 0);
        }

        // Field to create
        let body = gen_test_field_json("test_field1", "test_model");
        post_test_field(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field2", "test_model");
        post_test_field(&body, &pool).await;

        // Select Model with Fields
        {
            let mut tx = pool.begin().await.unwrap();
            let fields = field_select_by_model(&mut tx, "test_model").await.unwrap();

            assert_eq!(fields.len(), 2);
        }
    }

    /// Test field drop by model
    #[sqlx::test]
    async fn test_field_drop_by_model(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_param("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        // Field to create
        let body = gen_test_field_json("test_field1", "test_model");
        post_test_field(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field2", "test_model");
        post_test_field(&body, &pool).await;

        // Delete Model with Fields
        {
            let mut tx = pool.begin().await.unwrap();
            let fields = field_drop_by_model(&mut tx, "test_model").await.unwrap();

            tx.commit().await.unwrap();

            assert_eq!(fields.len(), 2);
        };

        // Delete Model with Fields, but none left
        {
            let mut tx = pool.begin().await.unwrap();
            let fields = field_select_by_model(&mut tx, "test_model").await.unwrap();

            tx.commit().await.unwrap();

            assert_eq!(fields.len(), 0);
        };
    }
}
