use crate::{
    auth::{Auth, TokenAuth},
    model::core::{
        model_add, model_add_with_fields, model_edit, model_read, model_read_search,
        model_read_with_fields, model_remove, model_remove_with_fields, Model, ModelFields,
        ModelFieldsParam, ModelParam, ModelSearch, ModelSearchParam,
    },
    util::Tag,
};
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{
    param::{Path, Query},
    payload::Json,
    OpenApi,
};
use sqlx::PgPool;

/// Struct we will build our REST API / Webserver
pub struct ModelApi;

#[OpenApi]
impl ModelApi {
    /// Add a model to the model table
    #[oai(path = "/model", method = "post", tag = Tag::Model)]
    async fn model_post(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Json(model_param): Json<ModelParam>,
    ) -> Result<Json<Model>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Add a model
        let model = model_add(&mut tx, &model_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(model))
    }

    /// Get a single model
    #[oai(path = "/model/:model_name", method = "get", tag = Tag::Model)]
    async fn model_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
    ) -> Result<Json<Model>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull model
        let model = model_read(&mut tx, &model_name).await?;

        Ok(Json(model))
    }

    /// Change a model to the model table
    #[oai(path = "/model/:model_name", method = "put", tag = Tag::Model)]
    async fn model_put(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
        Json(model_param): Json<ModelParam>,
    ) -> Result<Json<Model>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Run Model add logic
        let model = model_edit(&mut tx, &model_name, &model_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(model))
    }

    /// Delete a model
    #[oai(path = "/model/:model_name", method = "delete", tag = Tag::Model)]
    async fn model_delete(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
    ) -> Result<Json<Model>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Delete Model
        let model = model_remove(&mut tx, &model_name).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(model))
    }

    /// Search models
    #[oai(path = "/search/model", method = "get", tag = Tag::Search)]
    async fn model_get_search(
        &self,
        Data(pool): Data<&PgPool>,
        Query(model_name): Query<Option<String>>,
        Query(domain_name): Query<Option<String>>,
        Query(owner): Query<Option<String>>,
        Query(extra): Query<Option<String>>,
        Query(page): Query<Option<u64>>,
    ) -> Result<Json<ModelSearch>, poem::Error> {
        // Default no page to 0
        let page = page.unwrap_or(0);

        // Search Params
        let search_param = ModelSearchParam {
            model_name,
            domain_name,
            owner,
            extra,
        };

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull models
        let model_search = model_read_search(&mut tx, &search_param, &page).await?;

        Ok(Json(model_search))
    }

    /// Add a model to the model table
    #[oai(path = "/model_with_fields", method = "post", tag = Tag::ModelWithFields)]
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
    #[oai(path = "/model_with_fields/:model_name", method = "get", tag = Tag::ModelWithFields)]
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
    #[oai(path = "/model_with_fields/:model_name", method = "delete", tag = Tag::ModelWithFields)]
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

    /// Test create model
    #[sqlx::test]
    async fn test_model_post(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Payload to send into the API
        let body = gen_test_model_json("test_model", "test_domain");

        // Test Client
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .post("/model")
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
        json_value.object().get("name").assert_string("test_model");
        json_value.object().get("domain_id").assert_i64(1);
        json_value
            .object()
            .get("domain_name")
            .assert_string("test_domain");
        json_value
            .object()
            .get("owner")
            .assert_string("test_model@test.com");
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

    /// Test model post where no domain found
    #[sqlx::test]
    async fn test_model_post_not_found(pool: PgPool) {
        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Payload to send into the API
        let body = gen_test_model_json("test_model", "foobar_domain");

        // Test Client
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .post("/model")
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
        response.assert_text("domain does not exist").await;
    }

    /// Test double model create conflict
    #[sqlx::test]
    async fn test_model_post_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .post("/model")
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
            .assert_text("duplicate key value violates unique constraint \"model_name_key\"")
            .await;
    }

    /// Test model get
    #[sqlx::test]
    async fn test_model_get(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .get("/model/test_model")
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
        json_value.object().get("name").assert_string("test_model");
        json_value.object().get("domain_id").assert_i64(1);
        json_value
            .object()
            .get("domain_name")
            .assert_string("test_domain");
        json_value
            .object()
            .get("owner")
            .assert_string("test_model@test.com");
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

    /// Test Reading a model that does not exists
    #[sqlx::test]
    async fn test_model_get_not_found(pool: PgPool) {
        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .get("/model/test_model")
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

    /// Test model update
    #[sqlx::test]
    async fn test_model_put(pool: PgPool) {
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
        let body = gen_test_model_json("foobar_model", "test_domain");

        // Test Client
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .put("/model/test_model")
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
            .assert_string("foobar_model");
        json_value.object().get("domain_id").assert_i64(1);
        json_value
            .object()
            .get("domain_name")
            .assert_string("test_domain");
        json_value
            .object()
            .get("owner")
            .assert_string("foobar_model@test.com");
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

    /// Test model update when not found
    #[sqlx::test]
    async fn test_model_put_not_found(pool: PgPool) {
        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Payload to send into the API
        let body = gen_test_model_json("foobar_model", "test_domain");

        // Test Client
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .put("/model/test_model")
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
        response.assert_text("domain or model does not exist").await;
    }

    /// Test model update with Conflict
    #[sqlx::test]
    async fn test_model_put_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("foobar_model", "test_domain");
        post_test_model(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .put("/model/test_model")
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
            .assert_text("duplicate key value violates unique constraint \"model_name_key\"")
            .await;
    }

    /// Test model delete
    #[sqlx::test]
    async fn test_model_delete(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .delete("/model/test_model")
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
        json_value.object().get("name").assert_string("test_model");
        json_value.object().get("domain_id").assert_i64(1);
        json_value
            .object()
            .get("domain_name")
            .assert_string("test_domain");
        json_value
            .object()
            .get("owner")
            .assert_string("test_model@test.com");
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

    /// Test model delete if not exists
    #[sqlx::test]
    async fn test_model_delete_not_exists(pool: PgPool) {
        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .delete("/model/test_model")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .data(decoding_key)
            .data(user_creds)
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::NOT_FOUND);
        response.assert_text("model does not exist").await;
    }

    /// Test model delete if still have children
    #[sqlx::test]
    async fn test_model_delete_conflict(pool: PgPool) {
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
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .delete("/model/test_model")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .data(decoding_key)
            .data(user_creds)
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::CONFLICT);
        response.assert_text("update or delete on table \"model\" violates foreign key constraint \"field_model_id_fkey\" on table \"field\"").await;
    }

    /// Test model search
    #[sqlx::test]
    async fn test_model_get_search(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        for index in 0..50 {
            let body = gen_test_model_json(&format!("test_model_{}", index), "test_domain");
            post_test_model(&body, &pool).await;
        }

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("foobar_model", "foobar_domain");
        post_test_model(&body, &pool).await;

        // Test Client
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
        let cli = TestClient::new(ep);

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(50);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(true);
        }

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("page", &1)
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(1);
            json_value.object().get("page").assert_i64(1);
            json_value.object().get("more").assert_bool(false);
        }

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("model_name", &"test")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(50);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);
        }

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("model_name", &"abcdef")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(0);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);
        }

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("model_name", &"foobar")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(1);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);
        }

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("domain_name", &"test")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(50);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);
        }

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("model_name", &"foobar")
                .query("owner", &"test.com")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(1);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);

            json_value.object().get("models").object_array()[0]
                .get("name")
                .assert_string("foobar_model");
        }

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("model_name", &"foobar")
                .query("owner", &"test.com")
                .query("extra", &"abc")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(1);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);

            json_value.object().get("models").object_array()[0]
                .get("name")
                .assert_string("foobar_model");
        }
    }

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
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
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
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
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
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
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
