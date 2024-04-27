use crate::{
    core::{DbxDataType, Field, FieldParam, FieldParamUpdate},
    model::model_select,
};
use chrono::Utc;
use sqlx::{query, query_as, Postgres, Transaction};

/// Add a field to the field table
pub async fn field_insert(
    tx: &mut Transaction<'_, Postgres>,
    field_param: &FieldParam,
    username: &str,
) -> Result<Field, sqlx::Error> {
    let model = model_select(tx, &field_param.model_name).await?;

    query!(
        "INSERT INTO field (
            name,
            model_id,
            is_primary,
            data_type,
            is_nullable,
            precision,
            scale,
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
            $8,
            $9,
            $10,
            $11,
            $12
        )",
        field_param.name,
        model.id,
        field_param.is_primary,
        field_param.data_type as DbxDataType,
        field_param.is_nullable,
        field_param.precision,
        field_param.scale,
        field_param.extra,
        username,
        Utc::now(),
        username,
        Utc::now(),
    )
    .execute(&mut **tx)
    .await?;

    // Pull the row
    let field = field_select(tx, &model.name, &field_param.name).await?;

    Ok(field)
}

/// Pull one field
pub async fn field_select(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    field_name: &str,
) -> Result<Field, sqlx::Error> {
    let field = query_as!(
        Field,
        "SELECT
            id,
            name,
            model_id,
            model_name,
            seq,
            is_primary,
            data_type AS \"data_type!: DbxDataType\",
            is_nullable,
            precision,
            scale,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date
        FROM (
            SELECT
                field.id,
                field.name,
                field.model_id,
                model.name AS \"model_name\",
                ROW_NUMBER() OVER (ORDER BY field.id) as \"seq\",
                field.is_primary,
                field.data_type,
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
        ) wip
        WHERE
            name = $2",
        model_name,
        field_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(field)
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
        on
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

/// Update a field
pub async fn field_update(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    field_name: &str,
    field_param: &FieldParamUpdate,
    username: &str,
) -> Result<Field, sqlx::Error> {
    let model = model_select(tx, model_name).await?;

    let rows_affected = query!(
        "UPDATE
            field
        SET 
            name = $1,
            is_primary = $2,
            data_type = $3,
            is_nullable = $4,
            precision = $5,
            scale = $6,
            extra = $7,
            modified_by = $8,
            modified_date = $9
        WHERE
            model_id = $10
            AND name = $11",
        field_param.name,
        field_param.is_primary,
        field_param.data_type as DbxDataType,
        field_param.is_nullable,
        field_param.precision,
        field_param.scale,
        field_param.extra,
        username,
        Utc::now(),
        model.id,
        field_name,
    )
    .execute(&mut **tx)
    .await?
    .rows_affected();

    // Check if any rows were updated.
    if rows_affected == 0 {
        return Err(sqlx::Error::RowNotFound);
    }

    // Pull the row, but with the domain name added
    let field = field_select(tx, model_name, &field_param.name).await?;

    Ok(field)
}

/// Delete a field
pub async fn field_drop(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    field_name: &str,
) -> Result<Field, sqlx::Error> {
    // Pull the row and parent
    let model = model_select(tx, model_name).await?;
    let field = field_select(tx, model_name, field_name).await?;

    // Now run the delete since we have the row in memory
    query!(
        "DELETE FROM
            field
        WHERE
            model_id = $1
            AND name = $2",
        model.id,
        field_name,
    )
    .execute(&mut **tx)
    .await?;

    Ok(field)
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
    use crate::util::test_utils::{
        gen_test_domain_json, gen_test_model_json, post_test_domain, post_test_model,
    };
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use sqlx::PgPool;

    /// Create test Field
    fn gen_test_field_parm(name: &str, model_name: &str) -> FieldParam {
        FieldParam {
            name: name.to_string(),
            model_name: model_name.to_string(),
            is_primary: false,
            data_type: DbxDataType::Decimal,
            is_nullable: true,
            precision: Some(8),
            scale: Some(2),
            extra: json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        }
    }

    impl FieldParam {
        /// Turn FieldParam into FieldParamUpdate
        pub fn into_update(self) -> FieldParamUpdate {
            FieldParamUpdate {
                name: self.name,
                is_primary: self.is_primary,
                data_type: self.data_type,
                is_nullable: self.is_nullable,
                precision: self.precision,
                scale: self.scale,
                extra: self.extra,
            }
        }
    }

    /// Test create field
    #[sqlx::test]
    async fn test_field_insert(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        let field = {
            let mut tx = pool.begin().await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            let field = field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();

            field
        };

        assert_eq!(field.id, 1);
        assert_eq!(field.name, "test_field");
        assert_eq!(field.model_id, 1);
        assert_eq!(field.model_name, "test_model");
        assert_eq!(field.seq, Some(1));
        assert_eq!(field.is_primary, false);
        assert_eq!(field.data_type, DbxDataType::Decimal);
        assert_eq!(field.is_nullable, true);
        assert_eq!(field.precision, Some(8));
        assert_eq!(field.scale, Some(2));
        assert_eq!(
            field.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field.created_by, "test");
        assert_eq!(field.modified_by, "test");
    }

    /// Test field insert where no model found
    #[sqlx::test]
    async fn test_field_insert_not_found(pool: PgPool) {
        let err = {
            let field_param = gen_test_field_parm("test_field", "test_model");

            let mut tx = pool.begin().await.unwrap();
            field_insert(&mut tx, &field_param, "test")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test double field create conflict
    #[sqlx::test]
    async fn test_field_insert_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        let field_param = gen_test_field_parm("test_field", "test_model");
        {
            let mut tx = pool.begin().await.unwrap();

            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_insert(&mut tx, &field_param, "test")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "duplicate key value violates unique constraint \"field_model_id_name_key\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test field select
    #[sqlx::test]
    async fn test_field_select(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let field = {
            let mut tx = pool.begin().await.unwrap();
            field_select(&mut tx, "test_model", "test_field")
                .await
                .unwrap()
        };

        assert_eq!(field.id, 1);
        assert_eq!(field.name, "test_field");
        assert_eq!(field.model_id, 1);
        assert_eq!(field.model_name, "test_model");
        assert_eq!(field.seq, Some(1));
        assert_eq!(field.is_primary, false);
        assert_eq!(field.data_type, DbxDataType::Decimal);
        assert_eq!(field.is_nullable, true);
        assert_eq!(field.precision, Some(8));
        assert_eq!(field.scale, Some(2));
        assert_eq!(
            field.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field.created_by, "test");
        assert_eq!(field.modified_by, "test");
    }

    /// Test Reading a field that does not exists
    #[sqlx::test]
    async fn test_field_select_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_select(&mut tx, "test_field", "test_model")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
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
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let fields = field_select_by_model(&mut tx, "test_model").await.unwrap();

            assert_eq!(fields.len(), 0);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field2", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let fields = field_select_by_model(&mut tx, "test_model").await.unwrap();

            assert_eq!(fields.len(), 2);
        }
    }

    /// Test field update
    #[sqlx::test]
    async fn test_field_update(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("foobar_model", "foobar_domain");
        post_test_model(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let field = {
            let field_param = gen_test_field_parm("foobar_field", "test_model");

            let mut tx = pool.begin().await.unwrap();
            field_update(
                &mut tx,
                "test_model",
                "test_field",
                &field_param.into_update(),
                "foobar",
            )
            .await
            .unwrap()
        };

        assert_eq!(field.id, 1);
        assert_eq!(field.name, "foobar_field");
        assert_eq!(field.model_id, 1);
        assert_eq!(field.model_name, "test_model");
        assert_eq!(field.seq, Some(1));
        assert_eq!(field.is_primary, false);
        assert_eq!(field.data_type, DbxDataType::Decimal);
        assert_eq!(field.is_nullable, true);
        assert_eq!(field.precision, Some(8));
        assert_eq!(field.scale, Some(2));
        assert_eq!(
            field.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field.created_by, "test");
        assert_eq!(field.modified_by, "foobar");
    }

    /// Test field update where no field or model found
    #[sqlx::test]
    async fn test_field_update_not_found(pool: PgPool) {
        let err = {
            let field_param = gen_test_field_parm("test_field", "test_model");

            let mut tx = pool.begin().await.unwrap();
            field_update(
                &mut tx,
                "test_model",
                "test_field",
                &field_param.into_update(),
                "test",
            )
            .await
            .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };

        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        let err = {
            let field_param = gen_test_field_parm("foobar_field", "test_model");

            let mut tx = pool.begin().await.unwrap();
            field_update(
                &mut tx,
                "test_model",
                "test_field",
                &field_param.into_update(),
                "foobar",
            )
            .await
            .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test field update with conflict
    #[sqlx::test]
    async fn test_field_update_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("foobar_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();

            let field_param = gen_test_field_parm("foobar_field", "test_model");
            field_update(
                &mut tx,
                "test_model",
                "test_field",
                &field_param.into_update(),
                "foobar",
            )
            .await
            .unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "duplicate key value violates unique constraint \"field_model_id_name_key\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test field drop
    #[sqlx::test]
    async fn test_field_drop(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let field = {
            let mut tx = pool.begin().await.unwrap();
            let field = field_drop(&mut tx, "test_model", "test_field")
                .await
                .unwrap();

            tx.commit().await.unwrap();

            field
        };

        assert_eq!(field.id, 1);
        assert_eq!(field.name, "test_field");
        assert_eq!(field.model_id, 1);
        assert_eq!(field.model_name, "test_model");
        assert_eq!(field.seq, Some(1));
        assert_eq!(field.is_primary, false);
        assert_eq!(field.data_type, DbxDataType::Decimal);
        assert_eq!(field.is_nullable, true);
        assert_eq!(field.precision, Some(8));
        assert_eq!(field.scale, Some(2));
        assert_eq!(
            field.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field.created_by, "test");
        assert_eq!(field.modified_by, "test");

        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_select(&mut tx, "test_model", "test_field")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test field drop if not exists
    #[sqlx::test]
    async fn test_field_drop_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_drop(&mut tx, "test_model", "test_field")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test field drop by model
    #[sqlx::test]
    async fn test_field_drop_by_model(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field2", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let fields = {
            let mut tx = pool.begin().await.unwrap();
            let fields = field_drop_by_model(&mut tx, "test_model").await.unwrap();

            tx.commit().await.unwrap();

            fields
        };

        assert_eq!(fields.len(), 2);

        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_select(&mut tx, "test_model", "test_field")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }
}
