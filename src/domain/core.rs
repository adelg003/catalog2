use crate::{
    domain::db::{
        domain_drop, domain_insert, domain_select,  domain_update,
        model_select_by_domain, pack_select_by_domain,
    },
    model::Model,
    pack::Pack,
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

/// Domain with models and packs
#[derive(Object)]
pub struct DomainChildren {
    domain: Domain,
    models: Vec<Model>,
    packs: Vec<Pack>,
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
    domain_insert(tx, domain_param, username)
        .await
        .map_err(Conflict)
}

/// Read details of a domain
pub async fn domain_read(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<Domain, poem::Error> {
    // Pull domain
    domain_select(tx, domain_name).await.map_err(NotFound)
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
    match update {
        Ok(domain) => Ok(domain),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }
}

/// Remove a Domain
pub async fn domain_remove(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<Domain, poem::Error> {
    // Delete the domain
    let delete = domain_drop(tx, domain_name).await;

    // What result did we get?
    match delete {
        Ok(domain) => Ok(domain),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }
}

/// Read details of a domain and add model details for that domain
pub async fn domain_read_with_children(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<DomainChildren, poem::Error> {
    // Pull domain
    let domain = domain_read(tx, domain_name).await?;

    // Pull Models
    let models = model_select_by_domain(tx, &domain.name)
        .await
        .map_err(InternalServerError)?;

    // Pull Packs
    let packs = pack_select_by_domain(tx, &domain.name)
        .await
        .map_err(InternalServerError)?;

    Ok(DomainChildren {
        domain,
        models,
        packs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::util::test_utils::gen_test_domain_param,
        pack::{ComputeType, RuntimeType},
        util::test_utils::{
            gen_test_model_json, gen_test_pack_json, post_test_model, post_test_pack,
        },
    };
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use sqlx::PgPool;

    /// Test create domain
    #[sqlx::test]
    async fn test_domain_add(pool: PgPool) {
        let domain = {
            let domain_param = gen_test_domain_param("test_domain");

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
        let domain_param = gen_test_domain_param("test_domain");

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
            format!("{err}"),
            "error returned from database: duplicate key value violates unique constraint \"domain_name_key\""
        );
    }

    /// Test domain read
    #[sqlx::test]
    async fn test_domain_read(pool: PgPool) {
        {
            let domain_param = gen_test_domain_param("test_domain");

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
            format!("{err}"),
            "no rows returned by a query that expected to return at least one row"
        );
    }


    /// Test domain edit
    #[sqlx::test]
    async fn test_domain_edit(pool: PgPool) {
        {
            let domain_param = gen_test_domain_param("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let domain = {
            let domain_param = gen_test_domain_param("foobar_domain");

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
            let domain_param = gen_test_domain_param("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_edit(&mut tx, "test_domain", &domain_param, "test")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert_eq!(format!("{err}"), "domain does not exist");
    }

    /// Test domain update with conflict
    #[sqlx::test]
    async fn test_domain_edit_conflict(pool: PgPool) {
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
            domain_edit(&mut tx, "test_domain", &domain_param, "foobar")
                .await
                .unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::CONFLICT);
        assert_eq!(
            format!("{err}"),
            "duplicate key value violates unique constraint \"domain_name_key\""
        );
    }

    /// Test domain drop
    #[sqlx::test]
    async fn test_domain_remove(pool: PgPool) {
        {
            let domain_param = gen_test_domain_param("test_domain");

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
        assert_eq!(format!("{err}"), "domain does not exist");
    }

    /// Test domain drop if children not droppped
    #[sqlx::test]
    async fn test_domain_remove_conflict(pool: PgPool) {
        // Domain Creation
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_param("test_domain");
            domain_add(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_remove(&mut tx, "test_domain").await.unwrap_err()
        };

        assert_eq!(err.status(), StatusCode::CONFLICT);
        assert_eq!(
            format!("{err}"),
            "update or delete on table \"domain\" violates foreign key constraint \"model_domain_id_fkey\" on table \"model\"",
        );
    }

    /// Test Reading domain with models and packs
    #[sqlx::test]
    async fn test_domain_read_with_children(pool: PgPool) {
        // Domain Creation
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_param("test_domain");
            domain_add(&mut tx, &domain_param, "test_user")
                .await
                .unwrap();

            tx.commit().await.unwrap();
        }

        // Model to create
        let body = gen_test_model_json("test_model1", "test_domain");
        post_test_model(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model2", "test_domain");
        post_test_model(&body, &pool).await;

        // Pack to create
        let body = gen_test_pack_json("test_pack1", "test_domain");
        post_test_pack(&body, &pool).await;

        // Pack to create
        let body = gen_test_pack_json("test_pack2", "test_domain");
        post_test_pack(&body, &pool).await;

        let domain_with_children = {
            let mut tx = pool.begin().await.unwrap();
            domain_read_with_children(&mut tx, "test_domain")
                .await
                .unwrap()
        };

        let domain = domain_with_children.domain;
        let model1 = &domain_with_children.models[0];
        let model2 = &domain_with_children.models[1];
        let pack1 = &domain_with_children.packs[0];
        let pack2 = &domain_with_children.packs[1];

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
        assert_eq!(model1.created_by, "test_user");
        assert_eq!(model1.modified_by, "test_user");

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
        assert_eq!(model2.created_by, "test_user");
        assert_eq!(model2.modified_by, "test_user");

        assert_eq!(pack1.id, 1);
        assert_eq!(pack1.name, "test_pack1");
        assert_eq!(pack1.domain_id, 1);
        assert_eq!(pack1.domain_name, "test_domain");
        assert_eq!(pack1.runtime, RuntimeType::Docker);
        assert_eq!(pack1.compute, ComputeType::Dbx);
        assert_eq!(pack1.repo, "http://test.repo.org");
        assert_eq!(pack1.owner, "test_pack1@test.com");
        assert_eq!(
            pack1.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(pack1.created_by, "test_user");
        assert_eq!(pack1.modified_by, "test_user");

        assert_eq!(pack2.id, 2);
        assert_eq!(pack2.name, "test_pack2");
        assert_eq!(pack2.domain_id, 1);
        assert_eq!(pack2.domain_name, "test_domain");
        assert_eq!(pack2.runtime, RuntimeType::Docker);
        assert_eq!(pack2.compute, ComputeType::Dbx);
        assert_eq!(pack2.repo, "http://test.repo.org");
        assert_eq!(pack2.owner, "test_pack2@test.com");
        assert_eq!(
            pack2.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(pack2.created_by, "test_user");
        assert_eq!(pack2.modified_by, "test_user");
    }

    /// Test Reading domain with packs
    #[test]
    #[should_panic]
    fn test_domain_read_with_packs() {
        todo!();
    }
}
