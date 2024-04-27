use crate::{field::{Field, DbxDataType}, model::model_select};
use sqlx::{query, query_as, Postgres, Transaction};

/// Pull many fields by model
pub async fn field_select_by_model(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Vec<Field>, sqlx::Error> {
    let fields = query_as!(
        Field,
        "SELECT
            field.id,
            field.name,
            field.model_id,
            model.name AS \"model_name\",
            ROW_NUMBER() OVER (ORDER BY field.id) as \"seq\",
            field.is_primary,
            field.data_type AS \"data_type!: DbxDataType\",
            field.is_nullable,
            field.precision,
            field.scale,
            field.extra,
            field.created_by,
            field.created_date,
            field.modified_by,
            field.modified_date
        FROM
            field
        LEFT JOIN
            model
        on
            field.model_id = model.id 
        WHERE
            model.name = $1
        ORDER BY
            field.id",
        model_name,
    )
    .fetch_all(&mut **tx)
    .await?;

    Ok(fields)
}

/// Delete all field for a model
pub async fn field_drop_by_model(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Vec<Field>, sqlx::Error> {
    // Pull the rows and parent
    let model = model_select(tx, model_name).await?;
    let fields = field_select_by_model(tx, model_name).await?;

    // Now run the delete since we have the rows in memory
    query!(
        "DELETE FROM
            field
        WHERE
            model_id = $1",
        model.id,
    )
    .execute(&mut **tx)
    .await?;

    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_utils::{
        gen_test_domain_json, gen_test_field_json, gen_test_model_json, post_test_domain,
        post_test_field, post_test_model,
    };
    use pretty_assertions::assert_eq;
    use sqlx::PgPool;

    /// Test field select by model
    #[sqlx::test]
    async fn test_field_select_by_model(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();
            let fields = field_select_by_model(&mut tx, "test_model").await.unwrap();

            assert_eq!(fields.len(), 0);
        }

        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let fields = field_select_by_model(&mut tx, "test_model").await.unwrap();

            assert_eq!(fields.len(), 0);
        }

        // Field to create
        let body = gen_test_field_json("test_field1", "test_model");
        post_test_field(&body, &pool).await;

        //// Field to create
        //let body = gen_test_field_json("test_field2", "test_model");
        //post_test_field(&body, &pool).await;

        //{
        //    let mut tx = pool.begin().await.unwrap();
        //    let fields = field_select_by_model(&mut tx, "test_model").await.unwrap();

        //    assert_eq!(fields.len(), 2);
        //}
    }

    /// Test field drop by model
    #[sqlx::test]
    async fn test_field_drop_by_model(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field1", "test_model");
        post_test_field(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field2", "test_model");
        post_test_field(&body, &pool).await;

        let fields = {
            let mut tx = pool.begin().await.unwrap();
            let fields = field_drop_by_model(&mut tx, "test_model").await.unwrap();

            tx.commit().await.unwrap();

            fields
        };

        assert_eq!(fields.len(), 2);

        let fields = {
            let mut tx = pool.begin().await.unwrap();
            let fields = field_select_by_model(&mut tx, "test_model").await.unwrap();

            tx.commit().await.unwrap();

            fields
        };

        assert_eq!(fields.len(), 0);
    }
}
