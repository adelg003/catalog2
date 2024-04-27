use crate::{
    domain::{domain_read, Domain},
    domain_models::db::model_select_by_domain,
    model::Model,
};
use poem::error::InternalServerError;
use poem_openapi::Object;
use sqlx::{Postgres, Transaction};

/// Domain with models
#[derive(Object)]
pub struct DomainModels {
    domain: Domain,
    models: Vec<Model>,
}

/// Read details of a domain and add model details for that domain
pub async fn domain_read_with_models(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<DomainModels, poem::Error> {
    // Pull domain
    let domain = domain_read(tx, domain_name).await?;

    // Pull Models
    let models = model_select_by_domain(tx, &domain.name)
        .await
        .map_err(InternalServerError)?;

    Ok(DomainModels { domain, models })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_utils::{
        gen_test_domain_json, gen_test_model_json, post_test_domain, post_test_model,
    };
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use sqlx::PgPool;

    /// Test Reading domain with models
    #[sqlx::test]
    async fn test_domain_read_with_models(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model1", "test_domain");
        post_test_model(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model2", "test_domain");
        post_test_model(&body, &pool).await;

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
    }
}
