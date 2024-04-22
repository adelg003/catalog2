use crate::{
    domain::db::{domain_drop, domain_insert, domain_select, domain_select_search, domain_update},
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

const PAGE_SIZE: u64 = 50;

/// Domain Shared
#[derive(Debug, FromRow, Object)]
pub struct Domain {
    pub id: i32,
    pub name: String,
    pub owner: String,
    pub extra: serde_json::Value,
    pub created_by: String,
    pub created_date: DateTime<Utc>,
    pub modified_by: String,
    pub modified_date: DateTime<Utc>,
}

/// How to create a new domain
#[derive(Debug, Object, Serialize, Validate)]
pub struct DomainParam {
    #[validate(custom(function = dbx_validater))]
    pub name: String,
    #[validate(email)]
    pub owner: String,
    pub extra: serde_json::Value,
}

/// Domain Search Results
#[derive(Object)]
pub struct DomainSearch {
    domains: Vec<Domain>,
    page: u64,
    more: bool,
}

/// Add a domain
pub async fn domain_add(
    tx: &mut Transaction<'_, Postgres>,
    domain_param: &DomainParam,
    username: &str,
) -> Result<Domain, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    domain_param.validate().map_err(BadRequest)?;

    // Add new domain
    let domain = domain_insert(tx, domain_param, username)
        .await
        .map_err(Conflict)?;

    Ok(domain)
}

/// Read details of a domain
pub async fn domain_read(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<Domain, poem::Error> {
    // Pull domain
    let domain = domain_select(tx, domain_name).await.map_err(NotFound)?;

    Ok(domain)
}

/// Read details of many domains
pub async fn domain_read_search(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
    page: &u64,
) -> Result<DomainSearch, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;
    let next_offset = (page + 1) * PAGE_SIZE;

    // Pull the Domains
    let domains = domain_select_search(
        tx,
        domain_name,
        owner,
        extra,
        &Some(PAGE_SIZE),
        &Some(offset),
    )
    .await
    .map_err(InternalServerError)?;

    // More domains present?
    let next_domain = domain_select_search(
        tx,
        domain_name,
        owner,
        extra,
        &Some(PAGE_SIZE),
        &Some(next_offset),
    )
    .await
    .map_err(InternalServerError)?;

    let more = !next_domain.is_empty();

    Ok(DomainSearch {
        domains,
        page: *page,
        more,
    })
}

/// Edit a Domain
pub async fn domain_edit(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
    domain_param: &DomainParam,
    username: &str,
) -> Result<Domain, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    domain_param.validate().map_err(BadRequest)?;

    // Update domain
    let update = domain_update(tx, domain_name, domain_param, username).await;

    // What result did we get?
    let domain = match update {
        Ok(domain) => Ok(domain),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    Ok(domain)
}

/// Remove a Domain
pub async fn domain_remove(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
    //cascade: &bool,
) -> Result<Domain, poem::Error> {
    // Delete the domain
    let delete = domain_drop(tx, domain_name).await;

    // What result did we get?
    let domain = match delete {
        Ok(domain) => Ok(domain),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    Ok(domain)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{core::tests::gen_test_model_parm, db::model_insert};
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use sqlx::PgPool;

    /// Create test domain
    pub fn gen_test_domain_parm(name: &str) -> DomainParam {
        DomainParam {
            name: name.to_string(),
            owner: format!("{}@test.com", name),
            extra: json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        }
    }

    /// Test create domain
    #[sqlx::test]
    async fn test_domain_add(pool: PgPool) {
        let domain = {
            let domain_param = gen_test_domain_parm("test_domain");

            let mut tx = pool.begin().await.unwrap();
            let domain = domain_add(&mut tx, &domain_param, "test").await.unwrap();

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
    async fn test_domain_add_conflict(pool: PgPool) {
        let domain_param = gen_test_domain_parm("test_domain");

        {
            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_add(&mut tx, &domain_param, "test")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::CONFLICT);
        assert_eq!(
            format!("{}", err),
            "error returned from database: duplicate key value violates unique constraint \"domain_name_key\""
        );
    }

    /// Test domain read
    #[sqlx::test]
    async fn test_domain_read(pool: PgPool) {
        {
            let domain_param = gen_test_domain_parm("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let domain = {
            let mut tx = pool.begin().await.unwrap();
            domain_read(&mut tx, "test_domain").await.unwrap()
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
    async fn test_domain_read_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_read(&mut tx, "test_domain").await.unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            format!("{}", err),
            "no rows returned by a query that expected to return at least one row"
        );
    }

    /// Test domain search
    #[sqlx::test]
    async fn test_domain_read_search(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            for index in 0..50 {
                let domain_param = gen_test_domain_parm(&format!("test_domain_{}", index));
                domain_insert(&mut tx, &domain_param, "test").await.unwrap();
            }

            let domain_param = gen_test_domain_parm("foobar_domain");
            domain_insert(&mut tx, &domain_param, "foobar")
                .await
                .unwrap();

            tx.commit().await.unwrap();
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search = domain_read_search(&mut tx, &None, &None, &None, &0)
                .await
                .unwrap();

            assert_eq!(search.domains.len(), 50);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, true);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search = domain_read_search(&mut tx, &None, &None, &None, &1)
                .await
                .unwrap();

            assert_eq!(search.domains.len(), 1);
            assert_eq!(search.page, 1);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search = domain_read_search(&mut tx, &Some("abcdef".to_string()), &None, &None, &0)
                .await
                .unwrap();

            assert_eq!(search.domains.len(), 0);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search = domain_read_search(&mut tx, &Some("foobar".to_string()), &None, &None, &0)
                .await
                .unwrap();

            assert_eq!(search.domains.len(), 1);
            assert_eq!(search.domains[0].name, "foobar_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search = domain_read_search(
                &mut tx,
                &Some("foobar".to_string()),
                &Some("test.com".to_string()),
                &None,
                &0,
            )
            .await
            .unwrap();

            assert_eq!(search.domains.len(), 1);
            assert_eq!(search.domains[0].name, "foobar_domain");
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let search = domain_read_search(
                &mut tx,
                &Some("foobar".to_string()),
                &Some("test.com".to_string()),
                &Some("abc".to_string()),
                &0,
            )
            .await
            .unwrap();

            assert_eq!(search.domains.len(), 1);
            assert_eq!(search.domains[0].name, "foobar_domain");
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }
    }

    /// Test domain edit
    #[sqlx::test]
    async fn test_domain_edit(pool: PgPool) {
        {
            let domain_param = gen_test_domain_parm("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let domain = {
            let domain_param = gen_test_domain_parm("foobar_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_edit(&mut tx, "test_domain", &domain_param, "foobar")
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
    async fn test_domain_edit_not_found(pool: PgPool) {
        let err = {
            let domain_param = gen_test_domain_parm("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_edit(&mut tx, "test_domain", &domain_param, "test")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{}", err), "domain does not exist");
    }

    /// Test domain update with conflict
    #[sqlx::test]
    async fn test_domain_edit_conflict(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let domain_param = gen_test_domain_parm("foobar_domain");
            domain_insert(&mut tx, &domain_param, "foobar")
                .await
                .unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let domain_param = gen_test_domain_parm("foobar_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_edit(&mut tx, "test_domain", &domain_param, "foobar")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::CONFLICT);
        assert_eq!(
            format!("{}", err),
            "duplicate key value violates unique constraint \"domain_name_key\""
        );
    }

    /// Test domain drop
    #[sqlx::test]
    async fn test_domain_remove(pool: PgPool) {
        {
            let domain_param = gen_test_domain_parm("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let domain = {
            let mut tx = pool.begin().await.unwrap();
            let domain = domain_remove(&mut tx, "test_domain").await.unwrap();

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
    async fn test_domain_remove_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_remove(&mut tx, "test_domain").await.unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{}", err), "domain does not exist");
    }

    /// Test domain drop if children not droppped
    #[sqlx::test]
    async fn test_domain_remove_conflict(pool: PgPool) {
        {
            let domain_param = gen_test_domain_parm("test_domain");
            let model_param = gen_test_model_parm("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_remove(&mut tx, "test_domain").await.unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::CONFLICT);
        assert_eq!(
            format!("{}", err),
            "update or delete on table \"domain\" violates foreign key constraint \"model_domain_id_fkey\" on table \"model\"",
        );
    }
}
