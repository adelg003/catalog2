use crate::{
    api::Tag,
    auth::{Auth, TokenAuth},
    domain::core::{
        domain_add, domain_edit, domain_read, domain_read_search, domain_remove, Domain,
        DomainParam, DomainSearch,
    },
};
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{
    param::{Path, Query},
    payload::Json,
    OpenApi,
};
use sqlx::PgPool;

/// Struct we will build our REST API / Webserver
pub struct DomainApi;

#[OpenApi]
impl DomainApi {
    /// Add a domain to the domain table
    #[oai(path = "/domain", method = "post", tag = Tag::Domain)]
    async fn domain_post(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Json(domain_param): Json<DomainParam>,
    ) -> Result<Json<Domain>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Run Domain add logic
        let domain = domain_add(&mut tx, &domain_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(domain))
    }

    /// Get a single domain
    #[oai(path = "/domain/:domain_name", method = "get", tag = Tag::Domain)]
    async fn domain_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(domain_name): Path<String>,
    ) -> Result<Json<Domain>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull domain
        let domain = domain_read(&mut tx, &domain_name).await?;

        Ok(Json(domain))
    }

    /// Change a domain to the domain table
    #[oai(path = "/domain/:domain_name", method = "put", tag = Tag::Domain)]
    async fn domain_put(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(domain_name): Path<String>,
        Json(domain_param): Json<DomainParam>,
    ) -> Result<Json<Domain>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Run Domain add logic
        let domain = domain_edit(&mut tx, &domain_name, &domain_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(domain))
    }

    /// Delete a domain
    #[oai(path = "/domain/:domain_name", method = "delete", tag = Tag::Domain)]
    async fn domain_delete(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(domain_name): Path<String>,
    ) -> Result<Json<Domain>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull domain
        let domain = domain_remove(&mut tx, &domain_name).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(domain))
    }

    /// Search domains
    #[oai(path = "/search/domain", method = "get", tag = Tag::Search)]
    async fn domain_get_search(
        &self,
        Data(pool): Data<&PgPool>,
        Query(domain_name): Query<Option<String>>,
        Query(owner): Query<Option<String>>,
        Query(extra): Query<Option<String>>,
        Query(page): Query<Option<u64>>,
    ) -> Result<Json<DomainSearch>, poem::Error> {
        // Default no page to 0
        let page = page.unwrap_or(0);

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull domain
        let domain_search =
            domain_read_search(&mut tx, &domain_name, &owner, &extra, &page).await?;

        Ok(Json(domain_search))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_utils::{
        gen_jwt_encode_decode_token, gen_test_domain_json, gen_test_model_json,
        gen_test_user_creds, post_test_domain, post_test_model,
    };
    use poem::{http::StatusCode, test::TestClient};
    use poem_openapi::OpenApiService;

    /// Test create domain
    #[sqlx::test]
    async fn test_domain_post(pool: PgPool) {
        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Payload to send into the API
        let body = gen_test_domain_json("test_domain");

        // Test Client
        let ep = OpenApiService::new(DomainApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .post("/domain")
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
        json_value.object().get("name").assert_string("test_domain");
        json_value
            .object()
            .get("owner")
            .assert_string("test_domain@test.com");
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

    /// Test create domain twice
    #[sqlx::test]
    async fn test_domain_post_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(DomainApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Add conflicting record
        let response = cli
            .post("/domain")
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
        response.assert_text("error returned from database: duplicate key value violates unique constraint \"domain_name_key\"").await;
    }

    /// Test domain get
    #[sqlx::test]
    async fn test_domain_get(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Test Client
        let ep = OpenApiService::new(DomainApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .get("/domain/test_domain")
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
        json_value.object().get("name").assert_string("test_domain");
        json_value
            .object()
            .get("owner")
            .assert_string("test_domain@test.com");
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

    /// Test Reading a domain that does not exists
    #[sqlx::test]
    async fn test_domain_get_not_found(pool: PgPool) {
        // Test Client
        let ep = OpenApiService::new(DomainApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .get("/domain/test_domain")
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

    /// Test domain put
    #[sqlx::test]
    async fn test_domain_put(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Payload to send into the API
        let body = gen_test_domain_json("foobar_domain");

        // Test Client
        let ep = OpenApiService::new(DomainApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Update existing record
        let response = cli
            .put("/domain/test_domain")
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
            .assert_string("foobar_domain");
        json_value
            .object()
            .get("owner")
            .assert_string("foobar_domain@test.com");
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

    /// Test domain update where no domain found
    #[sqlx::test]
    async fn test_domain_put_not_found(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(DomainApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Add conflicting record
        let response = cli
            .put("/domain/test_domain")
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

    /// Test domain update with conflict
    #[sqlx::test]
    async fn test_domain_put_conflict(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(DomainApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Update existing record
        let response = cli
            .put("/domain/test_domain")
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
            .assert_text("duplicate key value violates unique constraint \"domain_name_key\"")
            .await;
    }

    /// Test domain drop
    #[sqlx::test]
    async fn test_domain_delete(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(DomainApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Delete existing record
        let response = cli
            .delete("/domain/test_domain")
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
        json_value.object().get("name").assert_string("test_domain");
        json_value
            .object()
            .get("owner")
            .assert_string("test_domain@test.com");
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

    /// Test domain drop if not exists
    #[sqlx::test]
    async fn test_domain_delete_not_found(pool: PgPool) {
        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(DomainApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Delete missing record
        let response = cli
            .delete("/domain/test_domain")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .data(decoding_key)
            .data(user_creds)
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::NOT_FOUND);
        response.assert_text("domain does not exist").await;
    }

    /// Test domain drop if children not droppped
    #[sqlx::test]
    async fn test_domain_remove_conflict(pool: PgPool) {
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
        let ep = OpenApiService::new(DomainApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Delete existing record
        let response = cli
            .delete("/domain/test_domain")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .data(decoding_key)
            .data(user_creds)
            .data(pool)
            .send()
            .await;

        // Check status
        response.assert_status(StatusCode::CONFLICT);
        response
            .assert_text("update or delete on table \"domain\" violates foreign key constraint \"model_domain_id_fkey\" on table \"model\"")
            .await;
    }

    /// Test domain search
    #[sqlx::test]
    async fn test_domain_get_search(pool: PgPool) {
        for index in 0..50 {
            // Domain to create
            let body = gen_test_domain_json(&format!("test_domain_{}", index));
            post_test_domain(&body, &pool).await;
        }

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        // Test Client
        let ep = OpenApiService::new(DomainApi, "test", "1.0");
        let cli = TestClient::new(ep);

        {
            // Test Request
            let response = cli
                .get("/search/domain")
                .header("Content-Type", "application/json; charset=utf-8")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("domains").array().assert_len(50);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(true);
        }

        {
            // Test Request
            let response = cli
                .get("/search/domain")
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

            json_value.object().get("domains").array().assert_len(1);
            json_value.object().get("page").assert_i64(1);
            json_value.object().get("more").assert_bool(false);
        }

        {
            // Test Request
            let response = cli
                .get("/search/domain")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("domain_name", &"abcdef")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("domains").array().assert_len(0);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);
        }

        {
            // Test Request
            let response = cli
                .get("/search/domain")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("domain_name", &"foobar")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("domains").array().assert_len(1);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);

            json_value.object().get("domains").object_array()[0]
                .get("name")
                .assert_string("foobar_domain");
        }

        {
            // Test Request
            let response = cli
                .get("/search/domain")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("domain_name", &"foobar")
                .query("owner", &"test.com")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("domains").array().assert_len(1);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);

            json_value.object().get("domains").object_array()[0]
                .get("name")
                .assert_string("foobar_domain");
        }

        {
            // Test Request
            let response = cli
                .get("/search/domain")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("domain_name", &"foobar")
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

            json_value.object().get("domains").array().assert_len(1);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);

            json_value.object().get("domains").object_array()[0]
                .get("name")
                .assert_string("foobar_domain");
        }
    }
}