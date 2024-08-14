use crate::{
    domain::core::{Domain, DomainParam, SearchDomainParam},
    model::Model,
    pack::{ComputeType, Pack, RuntimeType},
};
use chrono::Utc;
use sqlx::{query_as, Postgres, QueryBuilder, Transaction};

/// Add a domain to the domain table
pub async fn domain_insert(
    tx: &mut Transaction<'_, Postgres>,
    domain_param: &DomainParam,
    username: &str,
) -> Result<Domain, sqlx::Error> {
    let domain = query_as!(
        Domain,
        "INSERT INTO domain (
            name,
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
            $7
        ) RETURNING
            id,
            name,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date",
        domain_param.name,
        domain_param.owner,
        domain_param.extra,
        username,
        Utc::now(),
        username,
        Utc::now(),
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(domain)
}

/// Pull one domain
pub async fn domain_select(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<Domain, sqlx::Error> {
    let domain = query_as!(
        Domain,
        "SELECT
            id,
            name,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date
        FROM
            domain
        WHERE
            name = $1",
        domain_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(domain)
}

/// Update a domain
pub async fn domain_update(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
    domain_param: &DomainParam,
    username: &str,
) -> Result<Domain, sqlx::Error> {
    let domain = query_as!(
        Domain,
        "UPDATE
            domain
        SET 
            name = $1,
            owner = $2,
            extra = $3,
            modified_by = $4,
            modified_date = $5
        WHERE
            name = $6
        RETURNING
            id,
            name,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date",
        domain_param.name,
        domain_param.owner,
        domain_param.extra,
        username,
        Utc::now(),
        domain_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(domain)
}

/// Delete a domain
pub async fn domain_drop(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<Domain, sqlx::Error> {
    let domain = query_as!(
        Domain,
        "DELETE FROM
            domain
        WHERE
            name = $1
        RETURNING
            id,
            name,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date",
        domain_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(domain)
}

/// Pull many models by domain
pub async fn model_select_by_domain(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<Vec<Model>, sqlx::Error> {
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
            model.domain_id = schema.id
        WHERE
            domain.name = $1",
        domain_name,
    )
    .fetch_all(&mut **tx)
    .await?;

    Ok(model)
}

/// Pull many packs by domain
pub async fn pack_select_by_domain(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<Vec<Pack>, sqlx::Error> {
    let pack = query_as!(
        Pack,
        "SELECT
            pack.id,
            pack.name,
            pack.domain_id,
            domain.name AS \"domain_name\",
            pack.runtime AS \"runtime!: RuntimeType\",
            pack.compute AS \"compute!: ComputeType\",
            pack.repo,
            pack.owner,
            pack.extra,
            pack.created_by,
            pack.created_date,
            pack.modified_by,
            pack.modified_date
        FROM
            pack
        LEFT JOIN
            domain
        ON
            pack.domain_id = domain.id 
        WHERE
            domain.name = $1",
        domain_name,
    )
    .fetch_all(&mut **tx)
    .await?;

    Ok(pack)
}

/// Pull multiple domains that match by criteria
pub async fn search_domain_select(
    tx: &mut Transaction<'_, Postgres>,
    search_param: &SearchDomainParam,
    limit: &Option<u64>,
    offset: &Option<u64>,
) -> Result<Vec<Domain>, sqlx::Error> {
    // Query we will be modifying
    let mut query = QueryBuilder::<'_, Postgres>::new(
        "SELECT
            id,
            name,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date
        FROM
            domain",
    );

    // Should we add a WHERE statement?
    if search_param.domain_name.is_some()
        || search_param.owner.is_some()
        || search_param.extra.is_some()
    {
        query.push(" WHERE ");

        // Start building the WHERE statement with the "AND" separating the condition.
        let mut separated = query.separated(" AND ");

        // Fuzzy search
        if let Some(domain_name) = &search_param.domain_name {
            separated.push(format!("name ILIKE '%{domain_name}%'"));
        }
        if let Some(owner) = &search_param.owner {
            separated.push(format!("owner ILIKE '%{owner}%'"));
        }
        if let Some(extra) = &search_param.extra {
            separated.push(format!("extra::text ILIKE '%{extra}%'"));
        }
    }

    // Add ORDER BY
    query.push(" ORDER BY id ");

    // Add LIMIT
    if let Some(limit) = limit {
        query.push(format!(" LIMIT {limit} "));

        // Add OFFSET
        if let Some(offset) = offset {
            query.push(format!(" OFFSET {offset} "));
        }
    }

    // Run our generated SQL statement
    let domain = query
        .build_query_as::<Domain>()
        .fetch_all(&mut **tx)
        .await?;

    Ok(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::util::test_utils::gen_test_domain_param,
        util::test_utils::{
            gen_test_domain_json, gen_test_model_json, gen_test_schema_json, post_test_domain,
            post_test_model, post_test_schema,
        },
    };
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use sqlx::PgPool;

    /// Test create domain
    #[sqlx::test]
    async fn test_domain_insert(pool: PgPool) {
        let domain = {
            let domain_param = gen_test_domain_param("test_domain");

            let mut tx = pool.begin().await.unwrap();
            let domain = domain_insert(&mut tx, &domain_param, "test_user")
                .await
                .unwrap();

            tx.commit().await.unwrap();

            domain
        };

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
    }

    /// Test double domain create conflict
    #[sqlx::test]
    async fn test_domain_insert_conflict(pool: PgPool) {
        // Create a Domain
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let err = {
            let domain_param = gen_test_domain_param("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test_user")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "duplicate key value violates unique constraint \"domain_name_key\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test domain select
    #[sqlx::test]
    async fn test_domain_select(pool: PgPool) {
        // Create a Domain
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let domain = {
            let mut tx = pool.begin().await.unwrap();
            domain_select(&mut tx, "test_domain").await.unwrap()
        };

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
    }

    /// Test Reading a domain that does not exists
    #[sqlx::test]
    async fn test_domain_select_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_select(&mut tx, "test_domain").await.unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test domain update
    #[sqlx::test]
    async fn test_domain_update(pool: PgPool) {
        // Create a Domain
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let domain = {
            let domain_param = gen_test_domain_param("foobar_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_update(&mut tx, "test_domain", &domain_param, "foobar_user")
                .await
                .unwrap()
        };

        assert_eq!(domain.id, 1);
        assert_eq!(domain.name, "foobar_domain");
        assert_eq!(domain.owner, "foobar_domain@test.com");
        assert_eq!(
            domain.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(domain.created_by, "test_user");
        assert_eq!(domain.modified_by, "foobar_user");
    }

    /// Test domain update where no domain found
    #[sqlx::test]
    async fn test_domain_update_not_found(pool: PgPool) {
        let err = {
            let domain_param = gen_test_domain_param("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_update(&mut tx, "test_domain", &domain_param, "test_user")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test domain update with conflict
    #[sqlx::test]
    async fn test_domain_update_conflict(pool: PgPool) {
        // Create a Domain
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Create a Domain
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        let err = {
            let domain_param = gen_test_domain_param("foobar_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_update(&mut tx, "test_domain", &domain_param, "foobar_user")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "duplicate key value violates unique constraint \"domain_name_key\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test domain drop
    #[sqlx::test]
    async fn test_domain_drop(pool: PgPool) {
        // Create a Domain
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let domain = {
            let mut tx = pool.begin().await.unwrap();
            let domain = domain_drop(&mut tx, "test_domain").await.unwrap();

            tx.commit().await.unwrap();

            domain
        };

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

        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_select(&mut tx, "test_domain").await.unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test domain drop if not exists
    #[sqlx::test]
    async fn test_domain_drop_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_drop(&mut tx, "test_domain").await.unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test domain drop if children not droppped
    #[sqlx::test]
    async fn test_domain_drop_conflict(pool: PgPool) {
        // Create a Domain
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("test_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_drop(&mut tx, "test_domain").await.unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "update or delete on table \"domain\" violates foreign key constraint \"model_domain_id_fkey\" on table \"model\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test model select by domain
    #[sqlx::test]
    async fn test_model_select_by_domain(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_by_domain(&mut tx, "test_domain")
                .await
                .unwrap();

            assert_eq!(models.len(), 0);
        }

        // Create a Domain
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_by_domain(&mut tx, "test_domain")
                .await
                .unwrap();

            assert_eq!(models.len(), 0);
        }

        // Create a Schema
        let body = gen_test_schema_json("test_schema");
        post_test_schema(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("test_model", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

        // Create a Model
        let body = gen_test_model_json("test_model2", "test_domain", "test_schema");
        post_test_model(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_by_domain(&mut tx, "test_domain")
                .await
                .unwrap();

            assert_eq!(models.len(), 2);
        }
    }

    /// Test pack select by domain
    #[test]
    #[should_panic]
    fn test_pack_select_by_domain() {
        todo!();
    }

    /// Test domain search
    #[sqlx::test]
    async fn test_search_domain(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: None,
                owner: None,
                extra: None,
            };

            let domains = search_domain_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 2);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: Some("abcdef".to_string()),
                owner: None,
                extra: None,
            };

            let domains = search_domain_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 0);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: Some("test_domain".to_string()),
                owner: None,
                extra: None,
            };

            let domains = search_domain_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: Some("test_domain".to_string()),
                owner: Some("test.com".to_string()),
                extra: None,
            };

            let domains = search_domain_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: Some("test_domain".to_string()),
                owner: Some("test.com".to_string()),
                extra: Some("abc".to_string()),
            };

            let domains = search_domain_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: None,
                owner: None,
                extra: None,
            };

            let domains = search_domain_select(&mut tx, &search_param, &Some(1), &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: None,
                owner: None,
                extra: None,
            };

            let domains = search_domain_select(&mut tx, &search_param, &Some(1), &Some(1))
                .await
                .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "foobar_domain");
        }
    }
}
