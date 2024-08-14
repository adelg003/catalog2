use crate::{
    domain::domain_select,
    model::core::{Model, ModelParam, SearchModelParam},
    schema::schema_select,
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
    let schema = schema_select(tx, &model_param.schema_name).await?;

    query!(
        "INSERT INTO model (
            name,
            domain_id,
            schema_id,
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
            $8,
            $9
        )",
        model_param.name,
        domain.id,
        schema.id,
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
    // Make sure related domain and schema exists
    let domain = domain_select(tx, &model_param.domain_name).await?;
    let schema = schema_select(tx, &model_param.schema_name).await?;

    let rows_affected = query!(
        "UPDATE
            model
        SET 
            name = $1,
            domain_id = $2,
            schema_id = $3,
            owner = $4,
            extra = $5,
            modified_by = $6,
            modified_date = $7
        WHERE
            name = $8",
        model_param.name,
        domain.id,
        schema.id,
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

/// Pull multiple models that match the criteria
pub async fn search_model_select(
    tx: &mut Transaction<'_, Postgres>,
    params: &SearchModelParam,
    limit: &u64,
    offset: &u64,
) -> Result<Vec<Model>, sqlx::Error> {
    // Query we will be modifying
    let mut query = QueryBuilder::<'_, Postgres>::new(
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
            model.schema_id = schema.id",
    );

    // Should we add a WHERE statement?
    if search_param.model_name.is_some()
        || search_param.domain_name.is_some()
        || search_param.schema_name.is_some()
        || search_param.owner.is_some()
        || search_param.extra.is_some()
    {
        query.push(" WHERE ");

        // Start building the WHERE statement with the "AND" separating the condition.
        let mut separated = query.separated(" AND ");

        // Fuzzy search
        if let Some(model_name) = &params.model_name {
            separated.push(format!("model.name ILIKE '%{model_name}%'"));
        }
        if let Some(domain_name) = &params.domain_name {
            separated.push(format!("domain.name ILIKE '%{domain_name}%'"));
        }
        if let Some(schema_name) = &search_param.schema_name {
            separated.push(format!("schema.name ILIKE '%{schema_name}%'"));
        }
        if let Some(owner) = &search_param.owner {
            separated.push(format!("model.owner ILIKE '%{owner}%'"));
        }
        if let Some(extra) = &params.extra {
            separated.push(format!("model.extra::text ILIKE '%{extra}%'"));
        }
    }

    // Add ORDER BY
    match &params.ascending {
        true => query.push(" ORDER BY id "),
        false => query.push(" ORDER BY id DESC"),
    };

    // Add LIMIT and OFFSET
    query.push(format!(" LIMIT {limit} OFFSET {offset} "));

    // Run our generated SQL statement
    let model = query.build_query_as::<Model>().fetch_all(&mut **tx).await?;

    Ok(model)
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
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use sqlx::PgPool;

    /// Test create model
    #[sqlx::test]
    async fn test_model_insert(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Schema to create
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        let model = {
            let model_param = gen_test_model_param("test_model", "test_domain", "test_schema");

            let mut tx = pool.begin().await.unwrap();

            let model = model_insert(&mut tx, &model_param, "test_user")
                .await
                .unwrap();

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
            model_insert(&mut tx, &model_param, "test_user")
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

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("test_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

        let err = {
            let model_param = gen_test_model_param("test_model", "test_domain", "test_schema");
            let mut tx = pool.begin().await.unwrap();
            model_insert(&mut tx, &model_param, "test_user")
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

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("test_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

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
        assert_eq!(model.created_by, "test_user");
        assert_eq!(model.modified_by, "test_user");
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

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("test_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

        let model = {
            let model_param = gen_test_model_param("foobar_model", "foobar_domain", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            model_update(&mut tx, "test_model", &model_param, "foobar_user")
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
    async fn test_model_update_not_found(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let err = {
            let model_param = gen_test_model_param("test_model", "test_domain", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            model_update(&mut tx, "test_model", &model_param, "test_user")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("test_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

        let err = {
            let model_param = gen_test_model_param("test_model", "foobar_domain", "test_schema");

            let mut tx = pool.begin().await.unwrap();
            model_update(&mut tx, "test_model", &model_param, "foobar_user")
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
            model_update(&mut tx, "test_model", &model_param, "foobar_user")
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

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("test_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

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

    /// Test model search
    #[sqlx::test]
    async fn test_search_model(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

        let body = gen_test_model_json("test_model_2", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

        let body = gen_test_model_json("foobar_model", "foobar_domain", "test_schema");
        post_test_model(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: None,
                schema_name: None,
                owner: None,
                extra: None,
                ascending: true,
                page: 0,
            };

            let models = search_model_select(&mut tx, &search_param, &PAGE_SIZE, &0)
                .await
                .unwrap();

            assert_eq!(models.len(), 3);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model_2");
            assert_eq!(models[2].name, "foobar_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("abcdef".to_string()),
                domain_name: None,
                schema_name: None,
                owner: None,
                extra: None,
                ascending: true,
                page: 0,
            };

            let models = search_model_select(&mut tx, &search_param, &PAGE_SIZE, &0)
                .await
                .unwrap();

            assert_eq!(models.len(), 0);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("model".to_string()),
                domain_name: None,
                schema_name: None,
                owner: None,
                extra: None,
                ascending: true,
                page: 0,
            };

            let models = search_model_select(&mut tx, &search_param, &PAGE_SIZE, &0)
                .await
                .unwrap();

            assert_eq!(models.len(), 3);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model_2");
            assert_eq!(models[2].name, "foobar_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("model_2".to_string()),
                domain_name: None,
                schema_name: None,
                owner: None,
                extra: None,
                ascending: true,
                page: 0,
            };

            let models = search_model_select(&mut tx, &search_param, &PAGE_SIZE, &0)
                .await
                .unwrap();

            assert_eq!(models.len(), 1);
            assert_eq!(models[0].name, "test_model_2");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: Some("test_domain".to_string()),
                schema_name: None,
                owner: None,
                extra: None,
                ascending: true,
                page: 0,
            };

            let models = search_model_select(&mut tx, &search_param, &PAGE_SIZE, &0)
                .await
                .unwrap();

            assert_eq!(models.len(), 2);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model_2");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: None,
                schema_name: None,
                owner: Some("test_model%@test.com".to_string()),
                extra: None,
                ascending: true,
                page: 0,
            };

            let models = search_model_select(&mut tx, &search_param, &PAGE_SIZE, &0)
                .await
                .unwrap();

            assert_eq!(models.len(), 2);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model_2");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: None,
                schema_name: None,
                owner: None,
                extra: Some("abc".to_string()),
                ascending: true,
                page: 0,
            };

            let models = search_model_select(&mut tx, &search_param, &PAGE_SIZE, &0)
                .await
                .unwrap();

            assert_eq!(models.len(), 3);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model_2");
            assert_eq!(models[2].name, "foobar_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: None,
                schema_name: None,
                owner: None,
                extra: None,
                ascending: true,
                page: 0,
            };

            let models = search_model_select(&mut tx, &search_param, &1, &0)
                .await
                .unwrap();

            assert_eq!(models.len(), 1);
            assert_eq!(models[0].name, "test_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: None,
                schema_name: None,
                owner: None,
                extra: None,
                ascending: true,
                page: 0,
            };

            let models = search_model_select(&mut tx, &search_param, &1, &1)
                .await
                .unwrap();

            assert_eq!(models.len(), 1);
            assert_eq!(models[0].name, "test_model_2");
        }
    }
}
