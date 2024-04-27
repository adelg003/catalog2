use crate::model::Model;
use sqlx::{query_as, Postgres, Transaction};

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
    use crate::util::test_utils::{
        gen_test_domain_json, gen_test_model_json, post_test_domain, post_test_model,
    };
    use pretty_assertions::assert_eq;
    use sqlx::PgPool;

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
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

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
