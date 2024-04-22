use crate::{
    db::{
        field_drop, field_drop_by_model, field_insert, field_select, field_select_by_model,
        field_update, model_drop, model_insert, model_select, model_select_by_domain,
        model_select_search, model_update,
    },
    domain::{domain_read, Domain},
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

const PAGE_SIZE: u64 = 50;

impl Domain {
    /// Add model details to a domain
    async fn add_models(
        self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<DomainModels, poem::Error> {
        // Pull models
        let models = model_select_by_domain(tx, &self.name)
            .await
            .map_err(InternalServerError)?;

        Ok(DomainModels {
            domain: self,
            models,
        })
    }
}

/// Model to return via the API
#[derive(Debug, FromRow, Object)]
pub struct Model {
    pub id: i32,
    pub name: String,
    pub domain_id: i32,
    pub domain_name: String,
    pub owner: String,
    pub extra: serde_json::Value,
    pub created_by: String,
    pub created_date: DateTime<Utc>,
    pub modified_by: String,
    pub modified_date: DateTime<Utc>,
}

impl Model {
    /// Add fields details to a model
    async fn add_fields(
        self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<ModelFields, poem::Error> {
        // Pull models
        let fields = field_select_by_model(tx, &self.name)
            .await
            .map_err(InternalServerError)?;

        Ok(ModelFields {
            model: self,
            fields,
        })
    }
}

/// How to create a new model
#[derive(Object, Validate)]
pub struct ModelParam {
    #[validate(custom(function = dbx_validater))]
    pub name: String,
    pub domain_name: String,
    #[validate(email)]
    pub owner: String,
    pub extra: serde_json::Value,
}

/// Model Search Results
#[derive(Object)]
pub struct ModelSearch {
    models: Vec<Model>,
    page: u64,
    more: bool,
}

/// Domain with models
#[derive(Object)]
pub struct DomainModels {
    domain: Domain,
    models: Vec<Model>,
}

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
    pub model_id: i32,
    pub model_name: String,
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

/// How to create a new model
#[derive(Object, Validate)]
pub struct FieldParam {
    pub name: String,
    pub model_name: String,
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
        // Validate model and field names
        dbx_validater(&self.name)?;
        dbx_validater(&self.model_name)?;

        // Validate dtype parameters
        validate_data_type(&self.data_type, &self.precision, &self.scale)?;

        Ok(())
    }
}

/// How to update an existing model
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
        // Validate model and field names
        dbx_validater(&self.name)?;

        // Validate dtype parameters
        validate_data_type(&self.data_type, &self.precision, &self.scale)?;

        Ok(())
    }
}

/// Validate Datatype in Field
fn validate_data_type(
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

/// Field Search Results
#[derive(Object)]
pub struct FieldSearch {
    fields: Vec<Field>,
    page: u64,
    more: bool,
}

/// Model with fields
#[derive(Object)]
pub struct ModelFields {
    model: Model,
    fields: Vec<Field>,
}

/// Model with field parameters
#[derive(Object)]
pub struct ModelFieldsParam {
    model: ModelParam,
    fields: Vec<FieldParamModelChild>,
}

/// How to create a new field if bundled with the models
#[derive(Object)]
pub struct FieldParamModelChild {
    pub name: String,
    pub is_primary: bool,
    pub data_type: DbxDataType,
    pub is_nullable: bool,
    pub precision: Option<i32>,
    pub scale: Option<i32>,
    pub extra: serde_json::Value,
}

/// Read details of a domain and add model details for that domain
pub async fn domain_read_with_models(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<DomainModels, poem::Error> {
    // Pull domain_models
    let domain_models = domain_read(tx, domain_name).await?.add_models(tx).await?;

    Ok(domain_models)
}

/// Add a model
pub async fn model_add(
    tx: &mut Transaction<'_, Postgres>,
    model_param: &ModelParam,
    username: &str,
) -> Result<Model, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    model_param.validate().map_err(BadRequest)?;

    // Add Model
    let insert = model_insert(tx, model_param, username).await;

    // What result did we get?
    let model = match insert {
        Ok(model) => Ok(model),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    Ok(model)
}

/// Read details of a model
pub async fn model_read(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Model, poem::Error> {
    // Pull model
    let model: Model = model_select(tx, model_name).await.map_err(NotFound)?;

    Ok(model)
}

/// Read details of many models
pub async fn model_read_search(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &Option<String>,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
    page: &u64,
) -> Result<ModelSearch, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;
    let next_offset = (page + 1) * PAGE_SIZE;

    // Pull the Models
    let models = model_select_search(
        tx,
        model_name,
        domain_name,
        owner,
        extra,
        &Some(PAGE_SIZE),
        &Some(offset),
    )
    .await
    .map_err(InternalServerError)?;

    // More domains present?
    let next_model = model_select_search(
        tx,
        model_name,
        domain_name,
        owner,
        extra,
        &Some(PAGE_SIZE),
        &Some(next_offset),
    )
    .await
    .map_err(InternalServerError)?;

    let more = !next_model.is_empty();

    Ok(ModelSearch {
        models,
        page: *page,
        more,
    })
}
/// Edit a Model
pub async fn model_edit(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    model_param: &ModelParam,
    username: &str,
) -> Result<Model, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    model_param.validate().map_err(BadRequest)?;

    // Update domain
    let update = model_update(tx, model_name, model_param, username).await;

    // What result did we get?
    let model = match update {
        Ok(model) => Ok(model),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain or model does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    Ok(model)
}

/// Remove a Model
pub async fn model_remove(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Model, poem::Error> {
    // Delete the model
    let delete = model_drop(tx, model_name).await;

    // What result did we get?
    let model = match delete {
        Ok(model) => Ok(model),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "model does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    Ok(model)
}

/// Add a model with fields
pub async fn model_add_with_fields(
    tx: &mut Transaction<'_, Postgres>,
    param: &ModelFieldsParam,
    username: &str,
) -> Result<ModelFields, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    param.model.validate().map_err(BadRequest)?;

    // Add Model
    let model_insert = model_insert(tx, &param.model, username).await;

    // What result did we get?
    let model = match model_insert {
        Ok(model) => Ok(model),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    // Add Fields
    let mut fields = Vec::new();
    for wip in &param.fields {
        // Map to the full FieldParam
        let field_param = FieldParam {
            name: wip.name.clone(),
            model_name: model.name.clone(),
            is_primary: wip.is_primary,
            data_type: wip.data_type,
            is_nullable: wip.is_nullable,
            precision: wip.precision,
            scale: wip.scale,
            extra: wip.extra.clone(),
        };

        // Make sure the payload we got is good (check with Validate package).
        field_param.validate().map_err(BadRequest)?;

        // Insert the field
        let field_insert = field_insert(tx, &field_param, username).await;

        // What result did we get?
        let field = match field_insert {
            Ok(field) => Ok(field),
            // If this happens after just inserting a model, then its an us issue.
            Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
                "model does not exist",
                StatusCode::INTERNAL_SERVER_ERROR,
            )),
            Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
            Err(err) => Err(InternalServerError(err)),
        }?;

        fields.push(field);
    }

    Ok(ModelFields { model, fields })
}

/// Read details of a model and add fields details for that model
pub async fn model_read_with_fields(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<ModelFields, poem::Error> {
    // Pull domain_models
    let model_fields = model_select(tx, model_name)
        .await
        .map_err(NotFound)?
        .add_fields(tx)
        .await?;

    Ok(model_fields)
}

/// Delete a model with all its fields
pub async fn model_remove_with_fields(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<ModelFields, poem::Error> {
    // Delete all the fields
    let fields = field_drop_by_model(tx, model_name)
        .await
        .map_err(InternalServerError)?;

    // Delete the model
    let model = model_drop(tx, model_name).await.map_err(NotFound)?;

    Ok(ModelFields { model, fields })
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
    let field = match insert {
        Ok(field) => Ok(field),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "model does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    Ok(field)
}

/// Read details of a field
pub async fn field_read(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    field_name: &str,
) -> Result<Field, poem::Error> {
    // Pull field
    let field = field_select(tx, model_name, field_name)
        .await
        .map_err(NotFound)?;

    Ok(field)
}

/// Edit a Field
pub async fn field_edit(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    field_name: &str,
    field_param: &FieldParamUpdate,
    username: &str,
) -> Result<Field, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    field_param.validate().map_err(BadRequest)?;

    // Update domain
    let update = field_update(tx, model_name, field_name, field_param, username).await;

    // What result did we get?
    let field = match update {
        Ok(field) => Ok(field),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "model or field does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    Ok(field)
}

/// Remove a Field
pub async fn field_remove(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    field_name: &str,
) -> Result<Field, poem::Error> {
    // Delete the field
    let field = field_drop(tx, model_name, field_name)
        .await
        .map_err(NotFound)?;

    Ok(field)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::api::tests::{gen_test_domain_json, post_test_domain};
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use sqlx::PgPool;

    /// Create test model
    pub fn gen_test_model_parm(name: &str, domain_name: &str) -> ModelParam {
        ModelParam {
            name: name.to_string(),
            domain_name: domain_name.to_string(),
            owner: format!("{}@test.com", name),
            extra: json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        }
    }

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

    /// Test Reading domain with models
    #[sqlx::test]
    async fn test_domain_read_with_models(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model1", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model2", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let domain_with_models = {
            let mut tx = pool.begin().await.unwrap();
            domain_read_with_models(&mut tx, "test_domain")
                .await
                .unwrap()
        };

        let domain = domain_with_models.domain;
        let model1 = &domain_with_models.models[0];
        let model2 = &domain_with_models.models[1];

        assert_eq!(domain.id, 1);
        assert_eq!(domain.name, "test_domain");
        assert_eq!(domain.owner, "test_domain@test.com");
        assert_eq!(
            domain.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(domain.created_by, "test_user");
        assert_eq!(domain.modified_by, "test_user");

        assert_eq!(model1.id, 1);
        assert_eq!(model1.name, "test_model1");
        assert_eq!(model1.domain_id, 1);
        assert_eq!(model1.domain_name, "test_domain");
        assert_eq!(model1.owner, "test_model1@test.com");
        assert_eq!(
            model1.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(model1.created_by, "test");
        assert_eq!(model1.modified_by, "test");

        assert_eq!(model2.id, 2);
        assert_eq!(model2.name, "test_model2");
        assert_eq!(model2.domain_id, 1);
        assert_eq!(model2.domain_name, "test_domain");
        assert_eq!(model2.owner, "test_model2@test.com");
        assert_eq!(
            model2.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(model2.created_by, "test");
        assert_eq!(model2.modified_by, "test");
    }

    /// Test create model
    #[sqlx::test]
    async fn test_model_add(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let model = {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            let model = model_add(&mut tx, &model_param, "test").await.unwrap();

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
            let model_param = gen_test_model_parm("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_add(&mut tx, &model_param, "test").await.unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{}", err), "domain does not exist");
    }

    /// Test double model create conflict
    #[sqlx::test]
    async fn test_model_insert_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let model_param = gen_test_model_parm("test_model", "test_domain");
        {
            let mut tx = pool.begin().await.unwrap();

            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_add(&mut tx, &model_param, "test").await.unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::CONFLICT);
        assert_eq!(
            format!("{}", err),
            "duplicate key value violates unique constraint \"model_name_key\"",
        );
    }

    /// Test model select
    #[sqlx::test]
    async fn test_model_read(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let model_param = gen_test_model_parm("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let model = {
            let mut tx = pool.begin().await.unwrap();
            model_read(&mut tx, "test_model").await.unwrap()
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
    async fn test_model_read_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_read(&mut tx, "test_model").await.unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            format!("{}", err),
            "no rows returned by a query that expected to return at least one row",
        );
    }

    /// Test model search
    #[sqlx::test]
    async fn test_model_read_search(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            for index in 0..50 {
                let model_param =
                    gen_test_model_parm(&format!("test_model_{}", index), "test_domain");
                model_insert(&mut tx, &model_param, "test").await.unwrap();
            }

            let model_param = gen_test_model_parm("foobar_model", "foobar_domain");
            model_insert(&mut tx, &model_param, "foobar").await.unwrap();

            tx.commit().await.unwrap();
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search = model_read_search(&mut tx, &None, &None, &None, &None, &0)
                .await
                .unwrap();

            assert_eq!(search.models.len(), 50);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, true);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search = model_read_search(&mut tx, &None, &None, &None, &None, &1)
                .await
                .unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.page, 1);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search =
                model_read_search(&mut tx, &Some("test".to_string()), &None, &None, &None, &0)
                    .await
                    .unwrap();

            assert_eq!(search.models.len(), 50);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search = model_read_search(
                &mut tx,
                &Some("abcdef".to_string()),
                &None,
                &None,
                &None,
                &0,
            )
            .await
            .unwrap();

            assert_eq!(search.models.len(), 0);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search = model_read_search(
                &mut tx,
                &Some("foobar".to_string()),
                &None,
                &None,
                &None,
                &0,
            )
            .await
            .unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.models[0].name, "foobar_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search =
                model_read_search(&mut tx, &None, &Some("test".to_string()), &None, &None, &0)
                    .await
                    .unwrap();

            assert_eq!(search.models.len(), 50);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search = model_read_search(
                &mut tx,
                &Some("foobar".to_string()),
                &None,
                &Some("test.com".to_string()),
                &None,
                &0,
            )
            .await
            .unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.models[0].name, "foobar_model");
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search = model_read_search(
                &mut tx,
                &Some("foobar".to_string()),
                &None,
                &Some("test.com".to_string()),
                &Some("abc".to_string()),
                &0,
            )
            .await
            .unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.models[0].name, "foobar_model");
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }
    }

    /// Test model update
    #[sqlx::test]
    async fn test_model_edit(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let model = {
            let model_param = gen_test_model_parm("foobar_model", "foobar_domain");

            let mut tx = pool.begin().await.unwrap();
            model_edit(&mut tx, "test_model", &model_param, "foobar")
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
    async fn test_model_edit_not_found(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let err = {
            let model_param = gen_test_model_parm("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_edit(&mut tx, "test_model", &model_param, "test")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{}", err), "domain or model does not exist");

        {
            let model_param = gen_test_model_parm("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let model_param = gen_test_model_parm("test_model", "foobar_domain");

            let mut tx = pool.begin().await.unwrap();
            model_edit(&mut tx, "test_model", &model_param, "foobar")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{}", err), "domain or model does not exist");
    }

    /// Test model update with conflict
    #[sqlx::test]
    async fn test_model_edit_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("foobar_model", "test_domain");
            model_insert(&mut tx, &model_param, "foobar").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let model_param = gen_test_model_parm("foobar_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_edit(&mut tx, "test_model", &model_param, "foobar")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::CONFLICT);
        assert_eq!(
            format!("{}", err),
            "duplicate key value violates unique constraint \"model_name_key\"",
        );
    }

    /// Test model drop
    #[sqlx::test]
    async fn test_model_remove(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let model = {
            let mut tx = pool.begin().await.unwrap();
            let model = model_remove(&mut tx, "test_model").await.unwrap();

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
    async fn test_model_remove_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_remove(&mut tx, "test_model").await.unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{}", err), "model does not exist");
    }

    /// Test model drop if children not droppped
    #[sqlx::test]
    async fn test_model_remove_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_remove(&mut tx, "test_model").await.unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::CONFLICT);
        assert_eq!(
            format!("{}", err),
            "update or delete on table \"model\" violates foreign key constraint \"field_model_id_fkey\" on table \"field\"",
        );
    }

    /// Test adding a model with fields
    #[sqlx::test]
    async fn test_model_add_with_fields(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let model_fields = {
            let mut tx = pool.begin().await.unwrap();

            let model_field_params = ModelFieldsParam {
                model: gen_test_model_parm("test_model", "test_domain"),
                fields: vec![
                    FieldParamModelChild {
                        name: "test_field1".to_string(),
                        is_primary: false,
                        data_type: DbxDataType::Decimal,
                        is_nullable: true,
                        precision: Some(8),
                        scale: Some(2),
                        extra: json!({
                            "abc": 123,
                            "def": [1, 2, 3],
                        }),
                    },
                    FieldParamModelChild {
                        name: "test_field2".to_string(),
                        is_primary: false,
                        data_type: DbxDataType::Decimal,
                        is_nullable: true,
                        precision: Some(8),
                        scale: Some(2),
                        extra: json!({
                            "abc": 123,
                            "def": [1, 2, 3],
                        }),
                    },
                ],
            };

            let model_fields = model_add_with_fields(&mut tx, &model_field_params, "test")
                .await
                .unwrap();

            tx.commit().await.unwrap();

            model_fields
        };

        let model = model_fields.model;
        let field1 = &model_fields.fields[0];
        let field2 = &model_fields.fields[1];

        assert_eq!(model.id, 1);
        assert_eq!(model.name, "test_model");
        assert_eq!(model.domain_id, 1);
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

        assert_eq!(field1.id, 1);
        assert_eq!(field1.name, "test_field1");
        assert_eq!(field1.model_id, 1);
        assert_eq!(field1.model_name, "test_model");
        assert_eq!(field1.seq, Some(1));
        assert_eq!(field1.is_primary, false);
        assert_eq!(field1.data_type, DbxDataType::Decimal);
        assert_eq!(field1.is_nullable, true);
        assert_eq!(field1.precision, Some(8));
        assert_eq!(field1.scale, Some(2));
        assert_eq!(
            field1.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field1.created_by, "test");
        assert_eq!(field1.modified_by, "test");

        assert_eq!(field2.id, 2);
        assert_eq!(field2.name, "test_field2");
        assert_eq!(field2.model_id, 1);
        assert_eq!(field2.model_name, "test_model");
        assert_eq!(field2.seq, Some(2));
        assert_eq!(field2.is_primary, false);
        assert_eq!(field2.data_type, DbxDataType::Decimal);
        assert_eq!(field2.is_nullable, true);
        assert_eq!(field2.precision, Some(8));
        assert_eq!(field2.scale, Some(2));
        assert_eq!(
            field2.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field2.created_by, "test");
        assert_eq!(field2.modified_by, "test");

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

    /// Test Reading models with fields
    #[sqlx::test]
    async fn test_model_read_with_fiedls(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let model_param = gen_test_field_parm("test_field1", "test_model");
            field_insert(&mut tx, &model_param, "test").await.unwrap();

            let model_param = gen_test_field_parm("test_field2", "test_model");
            field_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let model_with_fields = {
            let mut tx = pool.begin().await.unwrap();
            model_read_with_fields(&mut tx, "test_model").await.unwrap()
        };

        let model = model_with_fields.model;
        let field1 = &model_with_fields.fields[0];
        let field2 = &model_with_fields.fields[1];

        assert_eq!(model.id, 1);
        assert_eq!(model.name, "test_model");
        assert_eq!(model.domain_id, 1);
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

        assert_eq!(field1.id, 1);
        assert_eq!(field1.name, "test_field1");
        assert_eq!(field1.model_id, 1);
        assert_eq!(field1.model_name, "test_model");
        assert_eq!(field1.seq, Some(1));
        assert_eq!(field1.is_primary, false);
        assert_eq!(field1.data_type, DbxDataType::Decimal);
        assert_eq!(field1.is_nullable, true);
        assert_eq!(field1.precision, Some(8));
        assert_eq!(field1.scale, Some(2));
        assert_eq!(
            field1.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field1.created_by, "test");
        assert_eq!(field1.modified_by, "test");

        assert_eq!(field2.id, 2);
        assert_eq!(field2.name, "test_field2");
        assert_eq!(field2.model_id, 1);
        assert_eq!(field2.model_name, "test_model");
        assert_eq!(field2.seq, Some(2));
        assert_eq!(field2.is_primary, false);
        assert_eq!(field2.data_type, DbxDataType::Decimal);
        assert_eq!(field2.is_nullable, true);
        assert_eq!(field2.precision, Some(8));
        assert_eq!(field2.scale, Some(2));
        assert_eq!(
            field2.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field2.created_by, "test");
        assert_eq!(field2.modified_by, "test");
    }

    /// Test field drop by model
    #[sqlx::test]
    async fn test_model_remove_with_fields(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field2", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let model_fields = {
            let mut tx = pool.begin().await.unwrap();
            let model_fields = model_remove_with_fields(&mut tx, "test_model")
                .await
                .unwrap();

            tx.commit().await.unwrap();

            model_fields
        };

        assert_eq!(model_fields.fields.len(), 2);

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

        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_select(&mut tx, "test_model", "test_field2")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };

        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_select(&mut tx, "test_model").await.unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test create field
    #[sqlx::test]
    async fn test_field_add(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let field = {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            let field = field_add(&mut tx, &field_param, "test").await.unwrap();

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
    async fn test_field_add_not_found(pool: PgPool) {
        let err = {
            let field_param = gen_test_field_parm("test_field", "test_model");

            let mut tx = pool.begin().await.unwrap();
            field_add(&mut tx, &field_param, "test").await.unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{}", err), "model does not exist");
    }

    /// Test double field create conflict
    #[sqlx::test]
    async fn test_field_add_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let field_param = gen_test_field_parm("test_field", "test_model");
        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_add(&mut tx, &field_param, "test").await.unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::CONFLICT);
        assert_eq!(
            format!("{}", err),
            "duplicate key value violates unique constraint \"field_model_id_name_key\"",
        );
    }

    /// Test field select
    #[sqlx::test]
    async fn test_field_read(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let field = {
            let mut tx = pool.begin().await.unwrap();
            field_read(&mut tx, "test_model", "test_field")
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
    async fn test_field_read_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_read(&mut tx, "test_field", "test_model")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            format!("{}", err),
            "no rows returned by a query that expected to return at least one row",
        );
    }

    /// Test field update
    #[sqlx::test]
    async fn test_field_edit(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("foobar_model", "foobar_domain");
            model_insert(&mut tx, &model_param, "foobar").await.unwrap();

            tx.commit().await.unwrap();
        }

        let field = {
            let field_param = gen_test_field_parm("foobar_field", "test_model");

            let mut tx = pool.begin().await.unwrap();
            field_edit(
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
    async fn test_field_edit_not_found(pool: PgPool) {
        let err = {
            let field_param = gen_test_field_parm("test_field", "test_model");

            let mut tx = pool.begin().await.unwrap();
            field_edit(
                &mut tx,
                "test_model",
                "test_field",
                &field_param.into_update(),
                "test",
            )
            .await
            .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{}", err), "model or field does not exist");

        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let field_param = gen_test_field_parm("foobar_field", "test_model");

            let mut tx = pool.begin().await.unwrap();
            field_edit(
                &mut tx,
                "test_model",
                "test_field",
                &field_param.into_update(),
                "foobar",
            )
            .await
            .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{}", err), "model or field does not exist");
    }

    /// Test field update with conflict
    #[sqlx::test]
    async fn test_field_edit_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("foobar_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();

            let field_param = gen_test_field_parm("foobar_field", "test_model");
            field_edit(
                &mut tx,
                "test_model",
                "test_field",
                &field_param.into_update(),
                "foobar",
            )
            .await
            .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::CONFLICT);
        assert_eq!(
            format!("{}", err),
            "duplicate key value violates unique constraint \"field_model_id_name_key\"",
        );
    }

    /// Test field drop
    #[sqlx::test]
    async fn test_field_remove(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let field = {
            let mut tx = pool.begin().await.unwrap();
            let field = field_remove(&mut tx, "test_model", "test_field")
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
    async fn test_field_remove_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_remove(&mut tx, "test_model", "test_field")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            format!("{}", err),
            "no rows returned by a query that expected to return at least one row",
        );
    }
}
