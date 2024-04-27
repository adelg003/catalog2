use crate::{
    field::{field_add, DbxDataType, Field, FieldParam},
    model::{model_add, model_read, model_remove, Model, ModelParam},
    model_fields::db::{field_drop_by_model, field_select_by_model},
};
use poem::error::{BadRequest, InternalServerError};
use poem_openapi::Object;
use sqlx::{Postgres, Transaction};
use validator::Validate;

/// Model with fields
#[derive(Object)]
pub struct ModelFields {
    model: Model,
    fields: Vec<Field>,
}

/// Model with field parameters
#[derive(Object)]
pub struct ModelFieldsParam {
    model: ModelParam,
    fields: Vec<FieldParamModelChild>,
}

/// How to create a new field if bundled with the models
#[derive(Object)]
pub struct FieldParamModelChild {
    pub name: String,
    pub is_primary: bool,
    pub data_type: DbxDataType,
    pub is_nullable: bool,
    pub precision: Option<i32>,
    pub scale: Option<i32>,
    pub extra: serde_json::Value,
}

/// Add a model with fields
pub async fn model_add_with_fields(
    tx: &mut Transaction<'_, Postgres>,
    param: &ModelFieldsParam,
    username: &str,
) -> Result<ModelFields, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    param.model.validate().map_err(BadRequest)?;

    // Add Model
    let model = model_add(tx, &param.model, username).await?;

    // Add Fields
    let mut fields = Vec::new();
    for wip in &param.fields {
        // Map to the full FieldParam
        let field_param = FieldParam {
            name: wip.name.clone(),
            model_name: model.name.clone(),
            is_primary: wip.is_primary,
            data_type: wip.data_type,
            is_nullable: wip.is_nullable,
            precision: wip.precision,
            scale: wip.scale,
            extra: wip.extra.clone(),
        };

        // Make sure the payload we got is good (check with Validate package).
        field_param.validate().map_err(BadRequest)?;

        // Insert the field
        let field = field_add(tx, &field_param, username).await?;

        fields.push(field);
    }

    Ok(ModelFields { model, fields })
}

/// Read details of a model and add fields details for that model
pub async fn model_read_with_fields(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<ModelFields, poem::Error> {
    // Pull model
    let model = model_read(tx, model_name).await?;

    // Pull models
    let fields = field_select_by_model(tx, model_name)
        .await
        .map_err(InternalServerError)?;

    Ok(ModelFields { model, fields })
}

/// Delete a model with all its fields
pub async fn model_remove_with_fields(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<ModelFields, poem::Error> {
    // Delete all the fields
    let fields = field_drop_by_model(tx, model_name)
        .await
        .map_err(InternalServerError)?;

    // Delete the model
    let model = model_remove(tx, model_name).await?;

    Ok(ModelFields { model, fields })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model_fields::ModelFieldsApi,
        util::test_utils::{
            gen_test_domain_json, gen_test_field_json, gen_test_model_json, post_test_domain,
            post_test_field, post_test_model,
        },
    };
    use poem::{http::StatusCode, test::TestClient};
    use poem_openapi::OpenApiService;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use sqlx::PgPool;

    /// Create test model
    fn gen_test_model_parm(name: &str, domain_name: &str) -> ModelParam {
        ModelParam {
            name: name.to_string(),
            domain_name: domain_name.to_string(),
            owner: format!("{}@test.com", name),
            extra: json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        }
    }

    /// Test adding a model with fields
    #[sqlx::test]
    async fn test_model_add_with_fields(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let model_fields = {
            let mut tx = pool.begin().await.unwrap();

            let model_field_params = ModelFieldsParam {
                model: gen_test_model_parm("test_model", "test_domain"),
                fields: vec![
                    FieldParamModelChild {
                        name: "test_field1".to_string(),
                        is_primary: false,
                        data_type: DbxDataType::Decimal,
                        is_nullable: true,
                        precision: Some(8),
                        scale: Some(2),
                        extra: json!({
                            "abc": 123,
                            "def": [1, 2, 3],
                        }),
                    },
                    FieldParamModelChild {
                        name: "test_field2".to_string(),
                        is_primary: false,
                        data_type: DbxDataType::Decimal,
                        is_nullable: true,
                        precision: Some(8),
                        scale: Some(2),
                        extra: json!({
                            "abc": 123,
                            "def": [1, 2, 3],
                        }),
                    },
                ],
            };

            let model_fields = model_add_with_fields(&mut tx, &model_field_params, "test")
                .await
                .unwrap();

            tx.commit().await.unwrap();

            model_fields
        };

        let model = model_fields.model;
        let field1 = &model_fields.fields[0];
        let field2 = &model_fields.fields[1];

        assert_eq!(model.id, 1);
        assert_eq!(model.name, "test_model");
        assert_eq!(model.domain_id, 1);
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

        assert_eq!(field1.id, 1);
        assert_eq!(field1.name, "test_field1");
        assert_eq!(field1.model_id, 1);
        assert_eq!(field1.model_name, "test_model");
        assert_eq!(field1.seq, Some(1));
        assert_eq!(field1.is_primary, false);
        assert_eq!(field1.data_type, DbxDataType::Decimal);
        assert_eq!(field1.is_nullable, true);
        assert_eq!(field1.precision, Some(8));
        assert_eq!(field1.scale, Some(2));
        assert_eq!(
            field1.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field1.created_by, "test");
        assert_eq!(field1.modified_by, "test");

        assert_eq!(field2.id, 2);
        assert_eq!(field2.name, "test_field2");
        assert_eq!(field2.model_id, 1);
        assert_eq!(field2.model_name, "test_model");
        assert_eq!(field2.seq, Some(2));
        assert_eq!(field2.is_primary, false);
        assert_eq!(field2.data_type, DbxDataType::Decimal);
        assert_eq!(field2.is_nullable, true);
        assert_eq!(field2.precision, Some(8));
        assert_eq!(field2.scale, Some(2));
        assert_eq!(
            field2.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field2.created_by, "test");
        assert_eq!(field2.modified_by, "test");

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

    /// Test Reading models with fields
    #[sqlx::test]
    async fn test_model_read_with_fields(pool: PgPool) {
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

        // Lets read a model with some fields
        let model_with_fields = {
            let mut tx = pool.begin().await.unwrap();
            model_read_with_fields(&mut tx, "test_model").await.unwrap()
        };

        let model = model_with_fields.model;
        let field1 = &model_with_fields.fields[0];
        let field2 = &model_with_fields.fields[1];

        assert_eq!(model.id, 1);
        assert_eq!(model.name, "test_model");
        assert_eq!(model.domain_id, 1);
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

        assert_eq!(field1.id, 1);
        assert_eq!(field1.name, "test_field1");
        assert_eq!(field1.model_id, 1);
        assert_eq!(field1.model_name, "test_model");
        assert_eq!(field1.seq, Some(1));
        assert_eq!(field1.is_primary, false);
        assert_eq!(field1.data_type, DbxDataType::Decimal);
        assert_eq!(field1.is_nullable, true);
        assert_eq!(field1.precision, Some(8));
        assert_eq!(field1.scale, Some(2));
        assert_eq!(
            field1.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field1.created_by, "test_user");
        assert_eq!(field1.modified_by, "test_user");

        assert_eq!(field2.id, 2);
        assert_eq!(field2.name, "test_field2");
        assert_eq!(field2.model_id, 1);
        assert_eq!(field2.model_name, "test_model");
        assert_eq!(field2.seq, Some(2));
        assert_eq!(field2.is_primary, false);
        assert_eq!(field2.data_type, DbxDataType::Decimal);
        assert_eq!(field2.is_nullable, true);
        assert_eq!(field2.precision, Some(8));
        assert_eq!(field2.scale, Some(2));
        assert_eq!(
            field2.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field2.created_by, "test_user");
        assert_eq!(field2.modified_by, "test_user");
    }

    /// Test field drop by model
    #[sqlx::test]
    async fn test_model_remove_with_fields(pool: PgPool) {
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

        let model_fields = {
            let mut tx = pool.begin().await.unwrap();
            let model_fields = model_remove_with_fields(&mut tx, "test_model")
                .await
                .unwrap();

            tx.commit().await.unwrap();

            model_fields
        };

        assert_eq!(model_fields.fields.len(), 2);

        // Test Client
        let ep = OpenApiService::new(ModelFieldsApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .get("/field/test_model/test_field1")
            .header("Content-Type", "application/json; charset=utf-8")
            .data(pool.clone())
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::NOT_FOUND);
        response.assert_text("not found").await;

        // Test Request
        let response = cli
            .get("/field/test_model/test_field2")
            .header("Content-Type", "application/json; charset=utf-8")
            .data(pool.clone())
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::NOT_FOUND);
        response.assert_text("not found").await;

        // Test Request
        let response = cli
            .get("/model/test_model")
            .header("Content-Type", "application/json; charset=utf-8")
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::NOT_FOUND);
        response.assert_text("not found").await;
    }
}
