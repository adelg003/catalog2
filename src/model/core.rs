use crate::{
    dependency::{dependencies_select, Dependency, DependencyType},
    field::{field_add, DbxDataType, Field, FieldParam},
    model::db::{
        field_drop_by_model, field_select_by_model, model_drop, model_insert, model_select,
        model_select_search, model_update,
    },
    util::{dbx_validater, PAGE_SIZE},
};
use chrono::{DateTime, Utc};
use poem::{
    error::{BadRequest, Conflict, InternalServerError, NotFound},
    http::StatusCode,
};
use poem_openapi::Object;
use serde::Serialize;
use sqlx::{FromRow, Postgres, Transaction};
use validator::Validate;

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

/// How to create a new model
#[derive(Debug, Object, Serialize, Validate)]
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

/// Params for searching for models
pub struct ModelSearchParam {
    pub model_name: Option<String>,
    pub domain_name: Option<String>,
    pub owner: Option<String>,
    pub extra: Option<String>,
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

/// Model with fields and dependencies
#[derive(Object)]
pub struct ModelChildren {
    model: Model,
    fields: Vec<Field>,
    dependencies: Vec<Dependency>,
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
    match insert {
        Ok(model) => Ok(model),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }
}

/// Read details of a model
pub async fn model_read(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Model, poem::Error> {
    // Pull model
    model_select(tx, model_name).await.map_err(NotFound)
}

/// Read details of many models
pub async fn model_read_search(
    tx: &mut Transaction<'_, Postgres>,
    search_param: &ModelSearchParam,
    page: &u64,
) -> Result<ModelSearch, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;
    let next_offset = (page + 1) * PAGE_SIZE;

    // Pull the Models
    let models = model_select_search(tx, search_param, &Some(PAGE_SIZE), &Some(offset))
        .await
        .map_err(InternalServerError)?;

    // More models present?
    let next_model = model_select_search(tx, search_param, &Some(PAGE_SIZE), &Some(next_offset))
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
    match update {
        Ok(model) => Ok(model),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain or model does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }
}

/// Remove a Model
pub async fn model_remove(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Model, poem::Error> {
    // Delete the model
    let delete = model_drop(tx, model_name).await;

    // What result did we get?
    match delete {
        Ok(model) => Ok(model),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "model does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }
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
    let model = model_add(tx, &param.model, username).await?;

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
        let field = field_add(tx, &field_param, username).await?;

        fields.push(field);
    }

    Ok(ModelFields { model, fields })
}

/// Read details of a model and add fields details for that model
pub async fn model_read_with_fields(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<ModelFields, poem::Error> {
    // Pull model
    let model = model_read(tx, model_name).await?;

    // Pull models
    let fields = field_select_by_model(tx, model_name)
        .await
        .map_err(InternalServerError)?;

    Ok(ModelFields { model, fields })
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
    let model = model_remove(tx, model_name).await?;

    Ok(ModelFields { model, fields })
}

/// Read details of a model, add fields details for that model, and add dependencies
pub async fn model_read_with_children(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<ModelChildren, poem::Error> {
    // Pull model
    let model = model_read(tx, model_name).await?;

    // Pull models
    let fields = field_select_by_model(tx, model_name)
        .await
        .map_err(InternalServerError)?;

    // Pull dependencies
    let dependencies = dependencies_select(tx, &DependencyType::Model, model_name)
        .await
        .map_err(InternalServerError)?;

    Ok(ModelChildren {
        model,
        fields,
        dependencies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        field::FieldApi,
        model::util::test_utils::gen_test_model_param,
        util::test_utils::{
            gen_test_domain_json, gen_test_field_json, post_test_domain, post_test_field,
        },
    };
    use poem::{http::StatusCode, test::TestClient};
    use poem_openapi::OpenApiService;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use sqlx::PgPool;

    /// Test create model
    #[sqlx::test]
    async fn test_model_add(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let model = {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_param("test_model", "test_domain");
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
            let model_param = gen_test_model_param("test_model", "test_domain");

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

        let model_param = gen_test_model_param("test_model", "test_domain");
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
            let model_param = gen_test_model_param("test_model", "test_domain");

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
                    gen_test_model_param(&format!("test_model_{}", index), "test_domain");
                model_insert(&mut tx, &model_param, "test").await.unwrap();
            }

            let model_param = gen_test_model_param("foobar_model", "foobar_domain");
            model_insert(&mut tx, &model_param, "foobar").await.unwrap();

            tx.commit().await.unwrap();
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = ModelSearchParam {
                model_name: None,
                domain_name: None,
                owner: None,
                extra: None,
            };

            let search = model_read_search(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 50);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, true);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = ModelSearchParam {
                model_name: None,
                domain_name: None,
                owner: None,
                extra: None,
            };

            let search = model_read_search(&mut tx, &search_param, &1).await.unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.page, 1);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = ModelSearchParam {
                model_name: Some("test".to_string()),
                domain_name: None,
                owner: None,
                extra: None,
            };

            let search = model_read_search(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 50);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = ModelSearchParam {
                model_name: Some("abcdef".to_string()),
                domain_name: None,
                owner: None,
                extra: None,
            };

            let search = model_read_search(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 0);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = ModelSearchParam {
                model_name: Some("foobar".to_string()),
                domain_name: None,
                owner: None,
                extra: None,
            };

            let search = model_read_search(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.models[0].name, "foobar_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = ModelSearchParam {
                model_name: None,
                domain_name: Some("test".to_string()),
                owner: None,
                extra: None,
            };

            let search = model_read_search(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 50);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = ModelSearchParam {
                model_name: Some("foobar".to_string()),
                domain_name: None,
                owner: Some("test.com".to_string()),
                extra: None,
            };

            let search = model_read_search(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.models[0].name, "foobar_model");
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = ModelSearchParam {
                model_name: Some("foobar".to_string()),
                domain_name: None,
                owner: Some("test.com".to_string()),
                extra: Some("abc".to_string()),
            };

            let search = model_read_search(&mut tx, &search_param, &0).await.unwrap();

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

            let model_param = gen_test_model_param("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let model = {
            let model_param = gen_test_model_param("foobar_model", "foobar_domain");

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
            let model_param = gen_test_model_param("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_edit(&mut tx, "test_model", &model_param, "test")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{}", err), "domain or model does not exist");

        {
            let model_param = gen_test_model_param("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let model_param = gen_test_model_param("test_model", "foobar_domain");

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

            let model_param = gen_test_model_param("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let model_param = gen_test_model_param("foobar_model", "test_domain");
            model_insert(&mut tx, &model_param, "foobar").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let model_param = gen_test_model_param("foobar_model", "test_domain");

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

            let model_param = gen_test_model_param("test_model", "test_domain");
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

            let model_param = gen_test_model_param("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let body = gen_test_field_json("test_field", "test_model");
        post_test_field(&body, &pool).await;

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
                model: gen_test_model_param("test_model", "test_domain"),
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
    async fn test_model_read_with_fields(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_param("test_model", "test_domain");
            model_add(&mut tx, &model_param, "test_user").await.unwrap();

            tx.commit().await.unwrap();
        };

        // Field to create
        let body = gen_test_field_json("test_field1", "test_model");
        post_test_field(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field2", "test_model");
        post_test_field(&body, &pool).await;

        // Lets read a model with some fields
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
        assert_eq!(model.created_by, "test_user");
        assert_eq!(model.modified_by, "test_user");

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
        assert_eq!(field1.created_by, "test_user");
        assert_eq!(field1.modified_by, "test_user");

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
        assert_eq!(field2.created_by, "test_user");
        assert_eq!(field2.modified_by, "test_user");
    }

    /// Test field drop by model
    #[sqlx::test]
    async fn test_model_remove_with_fields(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_param("test_model", "test_domain");
            model_add(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        };

        // Field to create
        let body = gen_test_field_json("test_field1", "test_model");
        post_test_field(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field2", "test_model");
        post_test_field(&body, &pool).await;

        // Remove Field by Model
        let model_fields = {
            let mut tx = pool.begin().await.unwrap();
            let model_fields = model_remove_with_fields(&mut tx, "test_model")
                .await
                .unwrap();

            tx.commit().await.unwrap();

            model_fields
        };

        assert_eq!(model_fields.fields.len(), 2);

        // Test Client
        let ep = OpenApiService::new(FieldApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .get("/field/test_model/test_field1")
            .header("Content-Type", "application/json; charset=utf-8")
            .data(pool.clone())
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::NOT_FOUND);
        response
            .assert_text("no rows returned by a query that expected to return at least one row")
            .await;

        // Test Request
        let response = cli
            .get("/field/test_model/test_field2")
            .header("Content-Type", "application/json; charset=utf-8")
            .data(pool.clone())
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::NOT_FOUND);
        response
            .assert_text("no rows returned by a query that expected to return at least one row")
            .await;

        // Test Request
        {
            let mut tx = pool.begin().await.unwrap();
            let err = model_read(&mut tx, "test_model").await.unwrap_err();

            assert_eq!(err.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                format!("{}", err),
                "no rows returned by a query that expected to return at least one row",
            );
        }
    }
}
