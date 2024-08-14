use crate::{
    field::core::{DbxDataType, Field, FieldParam, FieldParamUpdate},
    schema::schema_select,
};
use chrono::Utc;
use sqlx::{query, query_as, Postgres, Transaction};

/// Add a field to the field table
pub async fn field_insert(
    tx: &mut Transaction<'_, Postgres>,
    field_param: &FieldParam,
    username: &str,
) -> Result<Field, sqlx::Error> {
    let schema = schema_select(tx, &field_param.schema_name).await?;

    query!(
        "INSERT INTO field (
            name,
            schema_id,
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
        schema.id,
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
    let field = field_select(tx, &schema.name, &field_param.name).await?;

    Ok(field)
}

/// Pull one field
pub async fn field_select(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
    field_name: &str,
) -> Result<Field, sqlx::Error> {
    let field = query_as!(
        Field,
        "SELECT
            id,
            name,
            schema_id,
            schema_name,
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
                field.schema_id,
                schema.name AS \"schema_name\",
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
                schema
            ON
                field.schema_id = schema.id 
            WHERE
                schema.name = $1
        ) wip
        WHERE
            name = $2",
        schema_name,
        field_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(field)
}

/// Update a field
pub async fn field_update(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
    field_name: &str,
    field_param: &FieldParamUpdate,
    username: &str,
) -> Result<Field, sqlx::Error> {
    let schema = schema_select(tx, schema_name).await?;

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
            schema_id = $10
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
        schema.id,
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
    let field = field_select(tx, schema_name, &field_param.name).await?;

    Ok(field)
}

/// Delete a field
pub async fn field_drop(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
    field_name: &str,
) -> Result<Field, sqlx::Error> {
    // Pull the row and parent
    let schema = schema_select(tx, schema_name).await?;
    let field = field_select(tx, schema_name, field_name).await?;

    // Now run the delete since we have the row in memory
    query!(
        "DELETE FROM
            field
        WHERE
            schema_id = $1
            AND name = $2",
        schema.id,
        field_name,
    )
    .execute(&mut **tx)
    .await?;

    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_utils::{
        gen_test_domain_json, gen_test_field_json, gen_test_schema_json, post_test_domain,
        post_test_field, post_test_schema,
    };
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use sqlx::PgPool;

    /// Create test Field
    fn gen_test_field_parm(name: &str, schema_name: &str) -> FieldParam {
        FieldParam {
            name: name.to_string(),
            schema_name: schema_name.to_string(),
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

        // Schema to create
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        let field = {
            let mut tx = pool.begin().await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_schema");
            let field = field_insert(&mut tx, &field_param, "test_user")
                .await
                .unwrap();

            tx.commit().await.unwrap();

            field
        };

        assert_eq!(field.id, 1);
        assert_eq!(field.name, "test_field");
        assert_eq!(field.schema_id, 1);
        assert_eq!(field.schema_name, "test_schema");
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
        assert_eq!(field.created_by, "test_user");
        assert_eq!(field.modified_by, "test_user");
    }

    /// Test field insert where no schema found
    #[sqlx::test]
    async fn test_field_insert_not_found(pool: PgPool) {
        let err = {
            let field_param = gen_test_field_parm("test_field", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            field_insert(&mut tx, &field_param, "test_user")
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

        // Schema to create
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field", "test_schema");
        post_test_field(&body, &pool).await;

        let err = {
            let field_param = gen_test_field_parm("test_field", "test_schema");
            let mut tx = pool.begin().await.unwrap();
            field_insert(&mut tx, &field_param, "test_user")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "duplicate key value violates unique constraint \"field_schema_id_name_key\"",
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

        // Schema to create
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field", "test_schema");
        post_test_field(&body, &pool).await;

        let field = {
            let mut tx = pool.begin().await.unwrap();
            field_select(&mut tx, "test_schema", "test_field")
                .await
                .unwrap()
        };

        assert_eq!(field.id, 1);
        assert_eq!(field.name, "test_field");
        assert_eq!(field.schema_id, 1);
        assert_eq!(field.schema_name, "test_schema");
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
        assert_eq!(field.created_by, "test_user");
        assert_eq!(field.modified_by, "test_user");
    }

    /// Test Reading a field that does not exists
    #[sqlx::test]
    async fn test_field_select_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_select(&mut tx, "test_field", "test_schema")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test field update
    #[sqlx::test]
    async fn test_field_update(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Schema to create
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        // Schema to create
        let body = gen_test_schema_json("foobar_schema");
        post_test_schema(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field", "test_schema");
        post_test_field(&body, &pool).await;

        let field = {
            let field_param = gen_test_field_parm("foobar_field", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            field_update(
                &mut tx,
                "test_schema",
                "test_field",
                &field_param.into_update(),
                "foobar_user",
            )
            .await
            .unwrap()
        };

        assert_eq!(field.id, 1);
        assert_eq!(field.name, "foobar_field");
        assert_eq!(field.schema_id, 1);
        assert_eq!(field.schema_name, "test_schema");
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
        assert_eq!(field.created_by, "test_user");
        assert_eq!(field.modified_by, "foobar_user");
    }

    /// Test field update where no field or schema found
    #[sqlx::test]
    async fn test_field_update_not_found(pool: PgPool) {
        let err = {
            let field_param = gen_test_field_parm("test_field", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            field_update(
                &mut tx,
                "test_schema",
                "test_field",
                &field_param.into_update(),
                "test_user",
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

        // Schema to create
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        let err = {
            let field_param = gen_test_field_parm("foobar_field", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            field_update(
                &mut tx,
                "test_schema",
                "test_field",
                &field_param.into_update(),
                "foobar_user",
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

        // Schema to create
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field", "test_schema");
        post_test_field(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("foobar_field", "test_schema");
        post_test_field(&body, &pool).await;

        let err = {
            let mut tx = pool.begin().await.unwrap();

            let field_param = gen_test_field_parm("foobar_field", "test_schema");
            field_update(
                &mut tx,
                "test_schema",
                "test_field",
                &field_param.into_update(),
                "foobar_user",
            )
            .await
            .unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "duplicate key value violates unique constraint \"field_schema_id_name_key\"",
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

        // Schema to create
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field", "test_schema");
        post_test_field(&body, &pool).await;

        let field = {
            let mut tx = pool.begin().await.unwrap();
            let field = field_drop(&mut tx, "test_schema", "test_field")
                .await
                .unwrap();

            tx.commit().await.unwrap();

            field
        };

        assert_eq!(field.id, 1);
        assert_eq!(field.name, "test_field");
        assert_eq!(field.schema_id, 1);
        assert_eq!(field.schema_name, "test_schema");
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
        assert_eq!(field.created_by, "test_user");
        assert_eq!(field.modified_by, "test_user");

        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_select(&mut tx, "test_schema", "test_field")
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
            field_drop(&mut tx, "test_schema", "test_field")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }
}
