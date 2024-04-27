use crate::{
    util::Tag,
    auth::{Auth, TokenAuth},
    model_fields::core::{
        model_add_with_fields, model_read_with_fields, model_remove_with_fields, ModelFields,
        ModelFieldsParam,
    },
};
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{param::Path, payload::Json, OpenApi};
use sqlx::PgPool;

/// Struct we will build our REST API / Webserver
pub struct ModelFieldsApi;

#[OpenApi]
impl ModelFieldsApi {
    /// Add a model to the model table
    #[oai(path = "/model_with_fields", method = "post", tag = Tag::ModelFields)]
    async fn model_post_with_fields(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Json(param): Json<ModelFieldsParam>,
    ) -> Result<Json<ModelFields>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Add a model and its field
        let model_fields = model_add_with_fields(&mut tx, &param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(model_fields))
    }

    /// Get a single model and its fields
    #[oai(path = "/model_with_fields/:model_name", method = "get", tag = Tag::ModelFields)]
    async fn model_get_with_fields(
        &self,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
    ) -> Result<Json<ModelFields>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull domain
        let model_fields = model_read_with_fields(&mut tx, &model_name).await?;

        Ok(Json(model_fields))
    }

    /// Delete a model and it s fields
    #[oai(path = "/model_with_fields/:model_name", method = "delete", tag = Tag::ModelFields)]
    async fn model_delete_with_fields(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
    ) -> Result<Json<ModelFields>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Delete Model
        let model_fields = model_remove_with_fields(&mut tx, &model_name).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(model_fields))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_utils::{
        gen_jwt_encode_decode_token, gen_test_domain_json, gen_test_field_json,
        gen_test_model_json, gen_test_user_creds, post_test_domain, post_test_field,
        post_test_model,
    };
    use poem::{http::StatusCode, test::TestClient};
    use poem_openapi::OpenApiService;
    use serde_json::json;
    use sqlx::PgPool;

    /// Test adding a model with fields
    #[sqlx::test]
    async fn test_model_post_with_fields(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Payload to send into the API
        let body = json!({
            "model": gen_test_model_json("test_model", "test_domain"),
            "fields": [
                gen_test_field_json("test_field1", "test_model"),
                gen_test_field_json("test_field2", "test_model"),
            ],
        });

        // Test Client
        let ep = OpenApiService::new(ModelFieldsApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .post("/model_with_fields")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .body_json(&body)
            .data(decoding_key)
            .data(user_creds)
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status_is_ok();

        // Check Values
        let test_json = response.json().await;
        let json_value = test_json.value();

        let model_json = json_value.object().get("model");
        let field1_json = json_value.object().get("fields").array().get(0);
        let field2_json = json_value.object().get("fields").array().get(1);

        // Model Validation
        model_json.object().get("id").assert_i64(1);
        model_json.object().get("name").assert_string("test_model");
        model_json.object().get("domain_id").assert_i64(1);
        model_json
            .object()
            .get("domain_name")
            .assert_string("test_domain");
        model_json
            .object()
            .get("owner")
            .assert_string("test_model@test.com");
        model_json
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        model_json
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        model_json
            .object()
            .get("created_by")
            .assert_string("test_user");
        model_json
            .object()
            .get("modified_by")
            .assert_string("test_user");

        // Field 1 Validation
        field1_json.object().get("id").assert_i64(1);
        field1_json
            .object()
            .get("name")
            .assert_string("test_field1");
        field1_json.object().get("model_id").assert_i64(1);
        field1_json
            .object()
            .get("model_name")
            .assert_string("test_model");
        field1_json.object().get("seq").assert_i64(1);
        field1_json.object().get("is_primary").assert_bool(false);
        field1_json
            .object()
            .get("data_type")
            .assert_string("decimal");
        field1_json.object().get("is_nullable").assert_bool(true);
        field1_json.object().get("precision").assert_i64(8);
        field1_json.object().get("scale").assert_i64(2);
        field1_json
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        field1_json
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        field1_json
            .object()
            .get("created_by")
            .assert_string("test_user");
        field1_json
            .object()
            .get("modified_by")
            .assert_string("test_user");

        // Field 2 Validation
        field2_json.object().get("id").assert_i64(2);
        field2_json
            .object()
            .get("name")
            .assert_string("test_field2");
        field2_json.object().get("model_id").assert_i64(1);
        field2_json
            .object()
            .get("model_name")
            .assert_string("test_model");
        field2_json.object().get("seq").assert_i64(2);
        field2_json.object().get("is_primary").assert_bool(false);
        field2_json
            .object()
            .get("data_type")
            .assert_string("decimal");
        field2_json.object().get("is_nullable").assert_bool(true);
        field2_json.object().get("precision").assert_i64(8);
        field2_json.object().get("scale").assert_i64(2);
        field2_json
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        field2_json
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        field2_json
            .object()
            .get("created_by")
            .assert_string("test_user");
        field2_json
            .object()
            .get("modified_by")
            .assert_string("test_user");
    }

    /// Test Reading models with fields
    #[sqlx::test]
    async fn test_model_get_with_fields(pool: PgPool) {
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

        // Test Client
        let ep = OpenApiService::new(ModelFieldsApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .get("/model_with_fields/test_model")
            .header("Content-Type", "application/json; charset=utf-8")
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status_is_ok();

        // Check Values
        let test_json = response.json().await;
        let json_value = test_json.value();

        let model_json = json_value.object().get("model");
        let field1_json = json_value.object().get("fields").array().get(0);
        let field2_json = json_value.object().get("fields").array().get(1);

        // Model Validation
        model_json.object().get("id").assert_i64(1);
        model_json.object().get("name").assert_string("test_model");
        model_json.object().get("domain_id").assert_i64(1);
        model_json
            .object()
            .get("domain_name")
            .assert_string("test_domain");
        model_json
            .object()
            .get("owner")
            .assert_string("test_model@test.com");
        model_json
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        model_json
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        model_json
            .object()
            .get("created_by")
            .assert_string("test_user");
        model_json
            .object()
            .get("modified_by")
            .assert_string("test_user");

        // Field 1 Validation
        field1_json.object().get("id").assert_i64(1);
        field1_json
            .object()
            .get("name")
            .assert_string("test_field1");
        field1_json.object().get("model_id").assert_i64(1);
        field1_json
            .object()
            .get("model_name")
            .assert_string("test_model");
        field1_json.object().get("seq").assert_i64(1);
        field1_json.object().get("is_primary").assert_bool(false);
        field1_json
            .object()
            .get("data_type")
            .assert_string("decimal");
        field1_json.object().get("is_nullable").assert_bool(true);
        field1_json.object().get("precision").assert_i64(8);
        field1_json.object().get("scale").assert_i64(2);
        field1_json
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        field1_json
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        field1_json
            .object()
            .get("created_by")
            .assert_string("test_user");
        field1_json
            .object()
            .get("modified_by")
            .assert_string("test_user");

        // Field 2 Validation
        field2_json.object().get("id").assert_i64(2);
        field2_json
            .object()
            .get("name")
            .assert_string("test_field2");
        field2_json.object().get("model_id").assert_i64(1);
        field2_json
            .object()
            .get("model_name")
            .assert_string("test_model");
        field2_json.object().get("seq").assert_i64(2);
        field2_json.object().get("is_primary").assert_bool(false);
        field2_json
            .object()
            .get("data_type")
            .assert_string("decimal");
        field2_json.object().get("is_nullable").assert_bool(true);
        field2_json.object().get("precision").assert_i64(8);
        field2_json.object().get("scale").assert_i64(2);
        field2_json
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        field2_json
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        field2_json
            .object()
            .get("created_by")
            .assert_string("test_user");
        field2_json
            .object()
            .get("modified_by")
            .assert_string("test_user");
    }

    /// Test field drop by model
    #[sqlx::test]
    async fn test_model_delete_with_fields(pool: PgPool) {
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

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(ModelFieldsApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .delete("/model_with_fields/test_model")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .data(decoding_key.clone())
            .data(user_creds.clone())
            .data(pool.clone())
            .send()
            .await;

        // Check status
        response.assert_status_is_ok();

        // Check Values
        let test_json = response.json().await;
        let json_value = test_json.value();

        let model_json = json_value.object().get("model");
        let field1_json = json_value.object().get("fields").array().get(0);
        let field2_json = json_value.object().get("fields").array().get(1);

        // Model Validation
        model_json.object().get("id").assert_i64(1);
        model_json.object().get("name").assert_string("test_model");
        model_json.object().get("domain_id").assert_i64(1);
        model_json
            .object()
            .get("domain_name")
            .assert_string("test_domain");
        model_json
            .object()
            .get("owner")
            .assert_string("test_model@test.com");
        model_json
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        model_json
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        model_json
            .object()
            .get("created_by")
            .assert_string("test_user");
        model_json
            .object()
            .get("modified_by")
            .assert_string("test_user");

        // Field 1 Validation
        field1_json.object().get("id").assert_i64(1);
        field1_json
            .object()
            .get("name")
            .assert_string("test_field1");
        field1_json.object().get("model_id").assert_i64(1);
        field1_json
            .object()
            .get("model_name")
            .assert_string("test_model");
        field1_json.object().get("seq").assert_i64(1);
        field1_json.object().get("is_primary").assert_bool(false);
        field1_json
            .object()
            .get("data_type")
            .assert_string("decimal");
        field1_json.object().get("is_nullable").assert_bool(true);
        field1_json.object().get("precision").assert_i64(8);
        field1_json.object().get("scale").assert_i64(2);
        field1_json
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        field1_json
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        field1_json
            .object()
            .get("created_by")
            .assert_string("test_user");
        field1_json
            .object()
            .get("modified_by")
            .assert_string("test_user");

        // Field 2 Validation
        field2_json.object().get("id").assert_i64(2);
        field2_json
            .object()
            .get("name")
            .assert_string("test_field2");
        field2_json.object().get("model_id").assert_i64(1);
        field2_json
            .object()
            .get("model_name")
            .assert_string("test_model");
        field2_json.object().get("seq").assert_i64(2);
        field2_json.object().get("is_primary").assert_bool(false);
        field2_json
            .object()
            .get("data_type")
            .assert_string("decimal");
        field2_json.object().get("is_nullable").assert_bool(true);
        field2_json.object().get("precision").assert_i64(8);
        field2_json.object().get("scale").assert_i64(2);
        field2_json
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        field2_json
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        field2_json
            .object()
            .get("created_by")
            .assert_string("test_user");
        field2_json
            .object()
            .get("modified_by")
            .assert_string("test_user");

        // Test Request
        let response = cli
            .delete("/model_fields/test_model")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .data(decoding_key)
            .data(user_creds)
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::NOT_FOUND);
        response.assert_text("not found").await;
    }
}
