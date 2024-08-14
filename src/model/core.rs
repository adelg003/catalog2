use crate::{
    dependency::{dependencies_select, Dependency, DependencyType},
    model::db::{model_drop, model_insert, model_select, model_update, search_model_select},
    schema::{schema_read_with_fields, SchemaFields},
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
    pub schema_id: i32,
    pub schema_name: String,
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
    pub schema_name: String,
    #[validate(email)]
    pub owner: String,
    pub extra: serde_json::Value,
}

/// Model with schema, fields, and dependencies
#[derive(Object)]
pub struct ModelChildren {
    model: Model,
    schema: SchemaFields,
    dependencies: Vec<Dependency>,
}

/// Model Search Results
#[derive(Object)]
pub struct SearchModel {
    models: Vec<Model>,
    page: u64,
    more: bool,
}

/// Params for searching for models
pub struct SearchModelParam {
    pub model_name: Option<String>,
    pub domain_name: Option<String>,
    pub schema_name: Option<String>,
    pub owner: Option<String>,
    pub extra: Option<String>,
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
            "domain or schema does not exist",
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
    model_drop(tx, model_name).await.map_err(NotFound)
}

/// Read details of a model, add schema, field, and dependencies
pub async fn model_read_with_children(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<ModelChildren, poem::Error> {
    // Pull model
    let model = model_read(tx, model_name).await?;

    // Pull Schema
    let schema: SchemaFields = schema_read_with_fields(tx, &model.schema_name).await?;

    // Pull dependencies
    let dependencies = dependencies_select(tx, &DependencyType::Model, model_name)
        .await
        .map_err(InternalServerError)?;

    Ok(ModelChildren {
        model,
        schema,
        dependencies,
    })
}

/// Read details of many models
pub async fn search_model_read(
    tx: &mut Transaction<'_, Postgres>,
    search_param: &SearchModelParam,
    page: &u64,
) -> Result<SearchModel, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;
    let next_offset = (page + 1) * PAGE_SIZE;

    // Pull the Models
    let models = search_model_select(tx, search_param, &Some(PAGE_SIZE), &Some(offset))
        .await
        .map_err(InternalServerError)?;

    // More models present?
    let next_model = search_model_select(tx, search_param, &Some(PAGE_SIZE), &Some(next_offset))
        .await
        .map_err(InternalServerError)?;

    let more = !next_model.is_empty();

    Ok(SearchModel {
        models,
        page: *page,
        more,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::util::test_utils::gen_test_model_param,
        util::test_utils::{
            gen_test_domain_json, gen_test_model_json, gen_test_schema_json, post_test_domain,
            post_test_model, post_test_schema,
        },
    };
    use poem::http::StatusCode;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use sqlx::PgPool;

    /// Test create model
    #[sqlx::test]
    async fn test_model_add(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Schema to create
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        let model = {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_param("test_model", "test_domain", "test_schema");
            let model = model_add(&mut tx, &model_param, "test_user").await.unwrap();

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
        assert_eq!(model.created_by, "test_user");
        assert_eq!(model.modified_by, "test_user");
    }

    /// Test model insert where no domain found
    #[sqlx::test]
    async fn test_model_insert_not_found(pool: PgPool) {
        let err = {
            let model_param = gen_test_model_param("test_model", "test_domain", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            model_add(&mut tx, &model_param, "test_user")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{err}"), "domain or schema does not exist");
    }

    /// Test double model create conflict
    #[sqlx::test]
    async fn test_model_insert_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("test_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

        let err = {
            let model_param = gen_test_model_param("test_model", "test_domain", "test_schema");
            let mut tx = pool.begin().await.unwrap();
            model_add(&mut tx, &model_param, "test_user")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::CONFLICT);
        assert_eq!(
            format!("{err}"),
            "duplicate key value violates unique constraint \"model_name_key\"",
        );
    }

    /// Test model select
    #[sqlx::test]
    async fn test_model_read(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("test_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

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
        assert_eq!(model.created_by, "test_user");
        assert_eq!(model.modified_by, "test_user");
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
            format!("{err}"),
            "no rows returned by a query that expected to return at least one row",
        );
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

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("test_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

        let model = {
            let model_param = gen_test_model_param("foobar_model", "foobar_domain", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            model_edit(&mut tx, "test_model", &model_param, "foobar_user")
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
        assert_eq!(model.created_by, "test_user");
        assert_eq!(model.modified_by, "foobar_user");
    }

    /// Test model update where no domain or model found
    #[sqlx::test]
    async fn test_model_edit_not_found(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let err = {
            let model_param = gen_test_model_param("test_model", "test_domain", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            model_edit(&mut tx, "test_model", &model_param, "test_user")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{err}"), "domain or model does not exist");

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("test_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

        let err = {
            let model_param = gen_test_model_param("test_model", "foobar_domain", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            model_edit(&mut tx, "test_model", &model_param, "foobar_user")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{err}"), "domain or model does not exist");
    }

    /// Test model update with conflict
    #[sqlx::test]
    async fn test_model_edit_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("test_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("foobar_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

        let err = {
            let model_param = gen_test_model_param("foobar_model", "test_domain", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            model_edit(&mut tx, "test_model", &model_param, "foobar_user")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::CONFLICT);
        assert_eq!(
            format!("{err}"),
            "duplicate key value violates unique constraint \"model_name_key\"",
        );
    }

    /// Test model drop
    #[sqlx::test]
    async fn test_model_remove(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("test_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

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
        assert_eq!(model.created_by, "test_user");
        assert_eq!(model.modified_by, "test_user");

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
        assert_eq!(
            format!("{err}"),
            "no rows returned by a query that expected to return at least one row"
        );
    }

    /// Test model search
    #[sqlx::test]
    async fn test_search_model_read(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        {
            for index in 0..50 {
                // Model to create
                let body = gen_test_model_json(
                    &format!("test_model_{index}"),
                    "test_domain",
                    "test_schema",
                );
                post_test_model(&body, &pool).await;
            }

            // Model to create
            let body = gen_test_model_json("foobar_model", "foobar_domain", "test_schema");
            post_test_model(&body, &pool).await;
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: None,
                schema_name: None,
                owner: None,
                extra: None,
            };

            let search = search_model_read(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 50);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, true);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: None,
                schema_name: None,
                owner: None,
                extra: None,
            };

            let search = search_model_read(&mut tx, &search_param, &1).await.unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.page, 1);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("test_model".to_string()),
                domain_name: None,
                schema_name: None,
                owner: None,
                extra: None,
            };

            let search = search_model_read(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 50);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("abcdef".to_string()),
                domain_name: None,
                schema_name: None,
                owner: None,
                extra: None,
            };

            let search = search_model_read(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 0);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("foobar_model".to_string()),
                domain_name: None,
                schema_name: None,
                owner: None,
                extra: None,
            };

            let search = search_model_read(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.models[0].name, "foobar_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("test_model".to_string()),
                domain_name: None,
                schema_name: None,
                owner: None,
                extra: None,
            };

            let search = search_model_read(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 50);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("foobar_model".to_string()),
                domain_name: None,
                schema_name: None,
                owner: Some("test.com".to_string()),
                extra: None,
            };

            let search = search_model_read(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.models[0].name, "foobar_model");
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("foobar_model".to_string()),
                domain_name: None,
                schema_name: None,
                owner: Some("test.com".to_string()),
                extra: Some("abc".to_string()),
            };

            let search = search_model_read(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.models[0].name, "foobar_model");
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }
    }
}
