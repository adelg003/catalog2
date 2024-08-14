use crate::{
    field::db::{field_drop, field_insert, field_select, field_update},
    util::dbx_validater,
};
use chrono::{DateTime, Utc};
use poem::{
    error::{BadRequest, Conflict, InternalServerError, NotFound},
    http::StatusCode,
};
use poem_openapi::{Enum, Object};
use sqlx::{FromRow, Postgres, Transaction, Type};
use validator::{Validate, ValidationError};

/// Databrick Dataypes
/// https://learn.microsoft.com/en-us/azure/databricks/sql/language-manual/sql-ref-datatypes
#[derive(Clone, Copy, Debug, Enum, PartialEq, Type)]
#[oai(rename_all = "lowercase")]
#[sqlx(type_name = "dbx_data_type", rename_all = "lowercase")]
pub enum DbxDataType {
    BigInt,
    Binary,
    Boolean,
    Date,
    Decimal,
    Double,
    Float,
    Int,
    Interval,
    Void,
    SmallInt,
    String,
    Timestamp,
    TimestampNtz,
    TinyInt,
}

/// Field to return via the API
#[derive(Debug, FromRow, Object)]
pub struct Field {
    pub id: i32,
    pub name: String,
    pub schema_id: i32,
    pub schema_name: String,
    pub seq: Option<i64>,
    pub is_primary: bool,
    pub data_type: DbxDataType,
    pub is_nullable: bool,
    pub precision: Option<i32>,
    pub scale: Option<i32>,
    pub extra: serde_json::Value,
    pub created_by: String,
    pub created_date: DateTime<Utc>,
    pub modified_by: String,
    pub modified_date: DateTime<Utc>,
}

/// How to create a new Field
#[derive(Object, Validate)]
pub struct FieldParam {
    pub name: String,
    pub schema_name: String,
    pub is_primary: bool,
    pub data_type: DbxDataType,
    pub is_nullable: bool,
    pub precision: Option<i32>,
    pub scale: Option<i32>,
    pub extra: serde_json::Value,
}

impl FieldParam {
    /// Ensure only decimals get the precision and scale parameters
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate Schema and field names
        dbx_validater(&self.name)?;
        dbx_validater(&self.schema_name)?;

        // Validate dtype parameters
        validate_data_type(&self.data_type, &self.precision, &self.scale)?;

        Ok(())
    }
}

/// How to update an existing schema
#[derive(Object, Validate)]
pub struct FieldParamUpdate {
    pub name: String,
    pub is_primary: bool,
    pub data_type: DbxDataType,
    pub is_nullable: bool,
    pub precision: Option<i32>,
    pub scale: Option<i32>,
    pub extra: serde_json::Value,
}

impl FieldParamUpdate {
    /// Ensure only decimals get the precision and scale parameters
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate schema and field names
        dbx_validater(&self.name)?;

        // Validate dtype parameters
        validate_data_type(&self.data_type, &self.precision, &self.scale)?;

        Ok(())
    }
}

/// Validate Datatype in Field
pub fn validate_data_type(
    data_type: &DbxDataType,
    precision: &Option<i32>,
    scale: &Option<i32>,
) -> Result<(), ValidationError> {
    // Validate dtype parameters
    match (data_type, precision, scale) {
        (DbxDataType::Decimal, Some(_), Some(_)) => Ok(()),
        (
            DbxDataType::BigInt
            | DbxDataType::Binary
            | DbxDataType::Boolean
            | DbxDataType::Date
            | DbxDataType::Double
            | DbxDataType::Float
            | DbxDataType::Int
            | DbxDataType::Interval
            | DbxDataType::Void
            | DbxDataType::SmallInt
            | DbxDataType::String
            | DbxDataType::Timestamp
            | DbxDataType::TimestampNtz
            | DbxDataType::TinyInt,
            None,
            None,
        ) => Ok(()),
        _ => Err(ValidationError::new(
            "Only Deciaml data type should have scale and precision",
        )),
    }
}

/// Add a field
pub async fn field_add(
    tx: &mut Transaction<'_, Postgres>,
    field_param: &FieldParam,
    username: &str,
) -> Result<Field, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    field_param.validate().map_err(BadRequest)?;

    // Add Field
    let insert = field_insert(tx, field_param, username).await;

    // What result did we get?
    match insert {
        Ok(field) => Ok(field),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "schema does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }
}

/// Read details of a field
pub async fn field_read(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
    field_name: &str,
) -> Result<Field, poem::Error> {
    // Pull field
    field_select(tx, schema_name, field_name)
        .await
        .map_err(NotFound)
}

/// Edit a Field
pub async fn field_edit(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
    field_name: &str,
    field_param: &FieldParamUpdate,
    username: &str,
) -> Result<Field, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    field_param.validate().map_err(BadRequest)?;

    // Update domain
    let update = field_update(tx, schema_name, field_name, field_param, username).await;

    // What result did we get?
    match update {
        Ok(field) => Ok(field),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "schema or field does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }
}

/// Remove a Field
pub async fn field_remove(
    tx: &mut Transaction<'_, Postgres>,
    schema_name: &str,
    field_name: &str,
) -> Result<Field, poem::Error> {
    // Delete the field
    field_drop(tx, schema_name, field_name)
        .await
        .map_err(NotFound)
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

    /// Test Data Type Validater
    #[test]
    fn test_validate_data_type() {
        let failed_check =
            ValidationError::new("Only Deciaml data type should have scale and precision");

        assert_eq!(
            validate_data_type(&DbxDataType::BigInt, &None, &None),
            Ok(())
        );

        assert_eq!(
            validate_data_type(&DbxDataType::Decimal, &Some(8), &Some(6)),
            Ok(())
        );

        assert_eq!(
            validate_data_type(&DbxDataType::String, &Some(8), &Some(6)),
            Err(failed_check.clone())
        );

        assert_eq!(
            validate_data_type(&DbxDataType::Decimal, &None, &None),
            Err(failed_check)
        );
    }

    /// Test create field
    #[sqlx::test]
    async fn test_field_add(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Schema to create
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        let field = {
            let mut tx = pool.begin().await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_schema");
            let field = field_add(&mut tx, &field_param, "test_user").await.unwrap();

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
    async fn test_field_add_not_found(pool: PgPool) {
        let err = {
            let field_param = gen_test_field_parm("test_field", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            field_add(&mut tx, &field_param, "test_user").await.unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{err}"), "schema does not exist");
    }

    /// Test double field create conflict
    #[sqlx::test]
    async fn test_field_add_conflict(pool: PgPool) {
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
            field_add(&mut tx, &field_param, "test_user").await.unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::CONFLICT);
        assert_eq!(
            format!("{err}"),
            "duplicate key value violates unique constraint \"field_schema_id_name_key\"",
        );
    }

    /// Test field select
    #[sqlx::test]
    async fn test_field_read(pool: PgPool) {
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
            field_read(&mut tx, "test_schema", "test_field")
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
    async fn test_field_read_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_read(&mut tx, "test_field", "test_schema")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            format!("{err}"),
            "no rows returned by a query that expected to return at least one row",
        );
    }

    /// Test field update
    #[sqlx::test]
    async fn test_field_edit(pool: PgPool) {
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
            field_edit(
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
    async fn test_field_edit_not_found(pool: PgPool) {
        let err = {
            let field_param = gen_test_field_parm("test_field", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            field_edit(
                &mut tx,
                "test_schema",
                "test_field",
                &field_param.into_update(),
                "test_user",
            )
            .await
            .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{err}"), "schema or field does not exist");

        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Schema to create
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        let err = {
            let field_param = gen_test_field_parm("foobar_field", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            field_edit(
                &mut tx,
                "test_schema",
                "test_field",
                &field_param.into_update(),
                "foobar_user",
            )
            .await
            .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{err}"), "schema or field does not exist");
    }

    /// Test field update with conflict
    #[sqlx::test]
    async fn test_field_edit_conflict(pool: PgPool) {
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
            field_edit(
                &mut tx,
                "test_schema",
                "test_field",
                &field_param.into_update(),
                "foobar_user",
            )
            .await
            .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::CONFLICT);
        assert_eq!(
            format!("{err}"),
            "duplicate key value violates unique constraint \"field_schema_id_name_key\"",
        );
    }

    /// Test field drop
    #[sqlx::test]
    async fn test_field_remove(pool: PgPool) {
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
            let field = field_remove(&mut tx, "test_schema", "test_field")
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
    async fn test_field_remove_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_remove(&mut tx, "test_schema", "test_field")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            format!("{err}"),
            "no rows returned by a query that expected to return at least one row",
        );
    }
}
