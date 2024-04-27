use crate::{
    util::PAGE_SIZE,
    model::db::{model_drop, model_insert, model_select, model_select_search, model_update},
    util::dbx_validater,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::util::test_utils::gen_test_model_parm,
        util::test_utils::{
            gen_test_domain_json, gen_test_field_json, post_test_domain, post_test_field,
        },
    };
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
            assert!(search.more);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search = model_read_search(&mut tx, &None, &None, &None, &None, &1)
                .await
                .unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.page, 1);
            assert!(!search.more);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search =
                model_read_search(&mut tx, &Some("test".to_string()), &None, &None, &None, &0)
                    .await
                    .unwrap();

            assert_eq!(search.models.len(), 50);
            assert_eq!(search.page, 0);
            assert!(!search.more);
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
            assert!(!search.more);
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
            assert!(!search.more);
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
            assert!(!search.more);
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
            assert!(!search.more);
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
}
