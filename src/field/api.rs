use crate::{
    api::Tag,
    auth::{Auth, TokenAuth},
    field::core::{
        field_add, field_edit, field_read, field_remove, Field, FieldParam, FieldParamUpdate,
    },
};
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{param::Path, payload::Json, OpenApi};
use sqlx::PgPool;

/// Struct we will build our REST API / Webserver
pub struct FieldApi;

#[OpenApi]
impl FieldApi {
    /// Add a field to the field table
    #[oai(path = "/field", method = "post", tag = Tag::Field)]
    async fn field_post(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Json(field_param): Json<FieldParam>,
    ) -> Result<Json<Field>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Run Domain add logic
        let field = field_add(&mut tx, &field_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(field))
    }

    /// Get a single field
    #[oai(path = "/field/:model_name/:field_name", method = "get", tag = Tag::Field)]
    async fn field_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
        Path(field_name): Path<String>,
    ) -> Result<Json<Field>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull field
        let field = field_read(&mut tx, &model_name, &field_name).await?;

        Ok(Json(field))
    }

    /// Change a field to the field table
    #[oai(path = "/field/:model_name/:field_name", method = "put", tag = Tag::Field)]
    async fn field_put(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
        Path(field_name): Path<String>,
        Json(field_param): Json<FieldParamUpdate>,
    ) -> Result<Json<Field>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Run Model add logic
        let field = field_edit(&mut tx, &model_name, &field_name, &field_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(field))
    }

    /// Delete a field
    #[oai(path = "/field/:model_name/:field_name", method = "delete", tag = Tag::Field)]
    async fn field_delete(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
        Path(field_name): Path<String>,
    ) -> Result<Json<Field>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Delete Field
        let field = field_remove(&mut tx, &model_name, &field_name).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(field))
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
    use poem::{
        http::StatusCode,
        test::{TestClient, TestResponse},
    };
    use poem_openapi::OpenApiService;
    use sqlx::PgPool;

    /// Test create model
    #[sqlx::test]
    async fn test_field_post(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Payload to send into the API
        let body = gen_test_field_json("test_field", "test_model");

        // Test Client
        let ep = OpenApiService::new(FieldApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response: TestResponse = cli
            .post("/field")
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

        json_value.object().get("id").assert_i64(1);
        json_value.object().get("name").assert_string("test_field");
        json_value.object().get("model_id").assert_i64(1);
        json_value
            .object()
            .get("model_name")
            .assert_string("test_model");
        json_value.object().get("seq").assert_i64(1);
        json_value.object().get("is_primary").assert_bool(false);
        json_value
            .object()
            .get("data_type")
            .assert_string("decimal");
        json_value.object().get("is_nullable").assert_bool(true);
        json_value.object().get("precision").assert_i64(8);
        json_value.object().get("scale").assert_i64(2);
        json_value
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        json_value
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        json_value
            .object()
            .get("created_by")
            .assert_string("test_user");
        json_value
            .object()
            .get("modified_by")
            .assert_string("test_user");
    }

    /// Test field insert where no model found
    #[sqlx::test]
    async fn test_field_post_not_found(pool: PgPool) {
        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Payload to send into the API
        let body = gen_test_field_json("test_field", "test_model");

        // Test Client
        let ep = OpenApiService::new(FieldApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response: TestResponse = cli
            .post("/field")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .body_json(&body)
            .data(decoding_key)
            .data(user_creds)
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::NOT_FOUND);
        response.assert_text("model does not exist").await;
    }

    /// Test double field create conflict
    #[sqlx::test]
    async fn test_field_post_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        // Field to create, to collide
        let body = gen_test_field_json("test_field", "test_model");
        post_test_field(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Payload to send into the API
        let body = gen_test_field_json("test_field", "test_model");

        // Test Client
        let ep = OpenApiService::new(FieldApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response: TestResponse = cli
            .post("/field")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .body_json(&body)
            .data(decoding_key)
            .data(user_creds)
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::CONFLICT);
        response
            .assert_text(
                "duplicate key value violates unique constraint \"field_model_id_name_key\"",
            )
            .await;
    }

    /// Test field select
    #[sqlx::test]
    async fn test_field_read(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field", "test_model");
        post_test_field(&body, &pool).await;

        // Test Client
        let ep = OpenApiService::new(FieldApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response: TestResponse = cli
            .get("/field/test_model/test_field")
            .header("Content-Type", "application/json; charset=utf-8")
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status_is_ok();

        // Check Values
        let test_json = response.json().await;
        let json_value = test_json.value();

        json_value.object().get("id").assert_i64(1);
        json_value.object().get("name").assert_string("test_field");
        json_value.object().get("model_id").assert_i64(1);
        json_value
            .object()
            .get("model_name")
            .assert_string("test_model");
        json_value.object().get("seq").assert_i64(1);
        json_value.object().get("is_primary").assert_bool(false);
        json_value
            .object()
            .get("data_type")
            .assert_string("decimal");
        json_value.object().get("is_nullable").assert_bool(true);
        json_value.object().get("precision").assert_i64(8);
        json_value.object().get("scale").assert_i64(2);
        json_value
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        json_value
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        json_value
            .object()
            .get("created_by")
            .assert_string("test_user");
        json_value
            .object()
            .get("modified_by")
            .assert_string("test_user");
    }

    /// Test Reading a field that does not exists
    #[sqlx::test]
    async fn test_field_get_not_found(pool: PgPool) {
        // Test Client
        let ep = OpenApiService::new(FieldApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response: TestResponse = cli
            .get("/field/test_model/test_field")
            .header("Content-Type", "application/json; charset=utf-8")
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::NOT_FOUND);
        response
            .assert_text("no rows returned by a query that expected to return at least one row")
            .await;
    }

    /// Test field update
    #[sqlx::test]
    async fn test_field_put(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field", "test_model");
        post_test_field(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Payload to send into the API
        let body = gen_test_field_json("foobar_field", "test_model");

        // Test Client
        let ep = OpenApiService::new(FieldApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response: TestResponse = cli
            .put("/field/test_model/test_field")
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

        json_value.object().get("id").assert_i64(1);
        json_value
            .object()
            .get("name")
            .assert_string("foobar_field");
        json_value.object().get("model_id").assert_i64(1);
        json_value
            .object()
            .get("model_name")
            .assert_string("test_model");
        json_value.object().get("seq").assert_i64(1);
        json_value.object().get("is_primary").assert_bool(false);
        json_value
            .object()
            .get("data_type")
            .assert_string("decimal");
        json_value.object().get("is_nullable").assert_bool(true);
        json_value.object().get("precision").assert_i64(8);
        json_value.object().get("scale").assert_i64(2);
        json_value
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        json_value
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        json_value
            .object()
            .get("created_by")
            .assert_string("test_user");
        json_value
            .object()
            .get("modified_by")
            .assert_string("test_user");
    }

    /// Test field update where no field or model found
    #[sqlx::test]
    async fn test_field_put_not_found(pool: PgPool) {
        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Payload to send into the API
        let body = gen_test_field_json("test_field", "test_model");

        // Test Client
        let ep = OpenApiService::new(FieldApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response: TestResponse = cli
            .put("/field/test_model/test_field")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .body_json(&body)
            .data(decoding_key)
            .data(user_creds)
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::NOT_FOUND);
        response.assert_text("model or field does not exist").await;
    }

    /// Test field update with conflict
    #[sqlx::test]
    async fn test_field_put_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field", "test_model");
        post_test_field(&body, &pool).await;

        // Field to create, to collide
        let body = gen_test_field_json("foobar_field", "test_model");
        post_test_field(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(FieldApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response: TestResponse = cli
            .put("/field/test_model/test_field")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .body_json(&body)
            .data(decoding_key)
            .data(user_creds)
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::CONFLICT);
        response
            .assert_text(
                "duplicate key value violates unique constraint \"field_model_id_name_key\"",
            )
            .await;
    }

    /// Test field drop
    #[sqlx::test]
    async fn test_field_delete(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        // Field to create
        let body = gen_test_field_json("test_field", "test_model");
        post_test_field(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(FieldApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response: TestResponse = cli
            .delete("/field/test_model/test_field")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
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

        json_value.object().get("id").assert_i64(1);
        json_value.object().get("name").assert_string("test_field");
        json_value.object().get("model_id").assert_i64(1);
        json_value
            .object()
            .get("model_name")
            .assert_string("test_model");
        json_value.object().get("seq").assert_i64(1);
        json_value.object().get("is_primary").assert_bool(false);
        json_value
            .object()
            .get("data_type")
            .assert_string("decimal");
        json_value.object().get("is_nullable").assert_bool(true);
        json_value.object().get("precision").assert_i64(8);
        json_value.object().get("scale").assert_i64(2);
        json_value
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        json_value
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        json_value
            .object()
            .get("created_by")
            .assert_string("test_user");
        json_value
            .object()
            .get("modified_by")
            .assert_string("test_user");
    }

    /// Test field drop if not exists
    #[sqlx::test]
    async fn test_field_remove_not_found(pool: PgPool) {
        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(FieldApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response: TestResponse = cli
            .delete("/field/test_model/test_field")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .data(decoding_key)
            .data(user_creds)
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::NOT_FOUND);
        response
            .assert_text("no rows returned by a query that expected to return at least one row")
            .await;
    }
}
