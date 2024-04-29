use crate::{
    domain::core::{Domain, DomainParam},
    model::Model,
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

/// Pull multiple domains that match the criteria
pub async fn domain_select_search(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
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
    if domain_name.is_some() || owner.is_some() || extra.is_some() {
        query.push(" WHERE ");

        // Start building the WHERE statement with the "AND" separating the condition.
        let mut separated = query.separated(" AND ");

        // Fuzzy search
        if let Some(domain_name) = domain_name {
            separated.push(format!("name ILIKE '%{}%'", domain_name));
        }
        if let Some(owner) = owner {
            separated.push(format!("owner ILIKE '%{}%'", owner));
        }
        if let Some(extra) = extra {
            separated.push(format!("extra::text ILIKE '%{}%'", extra));
        }
    }

    // Add ORDER BY
    query.push(" ORDER BY id ");

    // Add LIMIT
    if let Some(limit) = limit {
        query.push(format!(" LIMIT {} ", limit));

        // Add OFFSET
        if let Some(offset) = offset {
            query.push(format!(" OFFSET {} ", offset));
        }
    }

    // Run our generated SQL statement
    let domain = query
        .build_query_as::<Domain>()
        .fetch_all(&mut **tx)
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
        on
            model.domain_id = domain.id
        WHERE
            domain.name = $1",
        domain_name,
    )
    .fetch_all(&mut **tx)
    .await?;

    Ok(model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::util::test_utils::gen_test_domain_param,
        util::test_utils::{gen_test_model_json, post_test_model},
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
            let domain = domain_insert(&mut tx, &domain_param, "test").await.unwrap();

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
        assert_eq!(domain.created_by, "test");
        assert_eq!(domain.modified_by, "test");
    }

    /// Test double domain create conflict
    #[sqlx::test]
    async fn test_domain_insert_conflict(pool: PgPool) {
        let domain_param = gen_test_domain_param("test_domain");

        {
            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test")
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
        {
            let domain_param = gen_test_domain_param("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

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
        assert_eq!(domain.created_by, "test");
        assert_eq!(domain.modified_by, "test");
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

    /// Test domain search
    #[sqlx::test]
    async fn test_domain_search(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_param("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let domain_param = gen_test_domain_param("foobar_domain");
            domain_insert(&mut tx, &domain_param, "foobar")
                .await
                .unwrap();

            tx.commit().await.unwrap();
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let domains = domain_select_search(&mut tx, &None, &None, &None, &None, &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 2);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let domains = domain_select_search(
                &mut tx,
                &Some("abcdef".to_string()),
                &None,
                &None,
                &None,
                &None,
            )
            .await
            .unwrap();

            assert_eq!(domains.len(), 0);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let domains = domain_select_search(
                &mut tx,
                &Some("test".to_string()),
                &None,
                &None,
                &None,
                &None,
            )
            .await
            .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let domains = domain_select_search(
                &mut tx,
                &Some("test".to_string()),
                &Some("test.com".to_string()),
                &None,
                &None,
                &None,
            )
            .await
            .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let domains = domain_select_search(
                &mut tx,
                &Some("test".to_string()),
                &Some("test.com".to_string()),
                &Some("abc".to_string()),
                &None,
                &None,
            )
            .await
            .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let domains = domain_select_search(&mut tx, &None, &None, &None, &Some(1), &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let domains = domain_select_search(&mut tx, &None, &None, &None, &Some(1), &Some(1))
                .await
                .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "foobar_domain");
        }
    }

    /// Test domain update
    #[sqlx::test]
    async fn test_domain_update(pool: PgPool) {
        {
            let domain_param = gen_test_domain_param("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let domain = {
            let domain_param = gen_test_domain_param("foobar_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_update(&mut tx, "test_domain", &domain_param, "foobar")
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
        assert_eq!(domain.created_by, "test");
        assert_eq!(domain.modified_by, "foobar");
    }

    /// Test domain update where no domain found
    #[sqlx::test]
    async fn test_domain_update_not_found(pool: PgPool) {
        let err = {
            let domain_param = gen_test_domain_param("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_update(&mut tx, "test_domain", &domain_param, "test")
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
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_param("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let domain_param = gen_test_domain_param("foobar_domain");
            domain_insert(&mut tx, &domain_param, "foobar")
                .await
                .unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let domain_param = gen_test_domain_param("foobar_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_update(&mut tx, "test_domain", &domain_param, "foobar")
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
        {
            let domain_param = gen_test_domain_param("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

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
        assert_eq!(domain.created_by, "test");
        assert_eq!(domain.modified_by, "test");

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
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_param("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let body = gen_test_model_json("test_model", "test_domain");
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

        // Domain to create
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_param("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_by_domain(&mut tx, "test_domain")
                .await
                .unwrap();

            assert_eq!(models.len(), 0);
        }

        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        let body = gen_test_model_json("test_model2", "test_domain");
        post_test_model(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_by_domain(&mut tx, "test_domain")
                .await
                .unwrap();

            assert_eq!(models.len(), 2);
        }
    }
}
