use crate::{
    auth::{make_jwt, Auth, TokenAuth, TokenOrBasicAuth},
    core::{
        domain_add, domain_edit, domain_read, domain_read_search, domain_read_with_models,
        domain_remove, field_add, field_edit, field_read, field_remove, model_add,
        model_add_with_fields, model_edit, model_read, model_read_search, model_read_with_fields,
        model_remove, model_remove_with_fields, Domain, DomainModels, DomainParam, DomainSearch,
        Field, FieldParam, FieldParamUpdate, Model, ModelFields, ModelFieldsParam, ModelParam,
        ModelSearch,
    },
};
use jsonwebtoken::EncodingKey;
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{
    param::{Path, Query},
    payload::{Json, PlainText},
    OpenApi, Tags,
};
use sqlx::PgPool;

#[derive(Tags)]
enum Tag {
    Auth,
    //TODO Component,
    Domain,
    #[oai(rename = "Domain With Models")]
    DomainWithModels,
    Field,
    Model,
    #[oai(rename = "Model With Fields")]
    ModelWithFields,
    Search,
}

/// Struct we will build our REST API / Webserver
pub struct Api;

#[OpenApi]
impl Api {
    /// Generate a fresh JWT
    #[oai(path = "/gen_token", method = "post", tag = Tag::Auth)]
    async fn gen_token(
        &self,
        auth: TokenOrBasicAuth,
        Data(encoding_key): Data<&EncodingKey>,
    ) -> Result<PlainText<String>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Get JWT
        let token = make_jwt(username, encoding_key).map_err(InternalServerError)?;

        Ok(PlainText(token))
    }

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

    /// Get a single domain and its models
    #[oai(path = "/domain_with_models/:domain_name", method = "get", tag = Tag::DomainWithModels)]
    async fn domain_get_with_models(
        &self,
        Data(pool): Data<&PgPool>,
        Path(domain_name): Path<String>,
    ) -> Result<Json<DomainModels>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull domain
        let domain = domain_read_with_models(&mut tx, &domain_name).await?;

        Ok(Json(domain))
    }

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

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull models
        let model_search =
            model_read_search(&mut tx, &model_name, &domain_name, &owner, &extra, &page).await?;

        Ok(Json(model_search))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::UserCred;
    use jsonwebtoken::DecodingKey;
    use poem::{http::StatusCode, test::TestClient, web::headers::Authorization};
    use poem_openapi::OpenApiService;
    use serde_json::json;

    /// Create the JWT tokens
    fn gen_test_encode_decode_tokens() -> (EncodingKey, DecodingKey) {
        // Test JWT secert and keys
        let jwt_key =
            b"N9&YMUGmNpP@dy$At6jv$CEoXRA5hEgNy%C3n4mVKQpDkJoFMZ5VxK#&e&7xrYrC5$nai73GE!dGKqxc";
        let encoding_key = EncodingKey::from_secret(jwt_key);
        let decoding_key = DecodingKey::from_secret(jwt_key);

        (encoding_key, decoding_key)
    }

    /// Create test users creds
    fn gen_test_user_creds(user: &str) -> Vec<UserCred> {
        // Test user Cred
        vec![UserCred {
            username: user.to_string(),
            hash: "$2b$12$QkHm2JiQg3WILPe0l/8Vqun7UVLqfSBLAzXiKbffGhs11RSqH7bjS".to_string(),
        }]
    }

    /// Create test domain
    fn gen_test_domain_parm(name: &str) -> DomainParam {
        DomainParam {
            name: name.to_string(),
            owner: format!("{}@test.com", name),
            extra: json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        }
    }

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

    /// Test creating a token
    #[tokio::test]
    async fn test_get_token_auth_basic() {
        // Test JWT keys and User Creds
        let (encoding_key, _) = gen_test_encode_decode_tokens();
        let user_creds = gen_test_user_creds("test_user");

        // Test Client
        let ep = OpenApiService::new(Api, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .post("/gen_token")
            .typed_header(Authorization::basic("test_user", "abc123"))
            .data(encoding_key)
            .data(user_creds)
            .send()
            .await;

        // Check status and Value
        response.assert_status_is_ok();
    }

    /// Test bad request for creating a token
    #[tokio::test]
    async fn test_get_token_auth_basic_bad() {
        // Test JWT keys and User Creds
        let (encoding_key, _) = gen_test_encode_decode_tokens();
        let user_creds = gen_test_user_creds("test_user");

        // Test Client
        let ep = OpenApiService::new(Api, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .post("/gen_token")
            .typed_header(Authorization::basic("test_user", "bad_password"))
            .data(encoding_key)
            .data(user_creds)
            .send()
            .await;

        // Check status and Value
        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    /// Test creating a token
    #[tokio::test]
    async fn test_get_token_auth_token() {
        // Test JWT keys and User Creds
        let (encoding_key, decoding_key) = gen_test_encode_decode_tokens();
        let user_creds = gen_test_user_creds("test_user");

        // Test JWT
        let token = make_jwt("test_user", &encoding_key).unwrap();

        // Test Client
        let ep = OpenApiService::new(Api, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .post("/gen_token")
            .header("X-API-Key", &token)
            .data(encoding_key)
            .data(decoding_key)
            .data(user_creds)
            .send()
            .await;

        // Check status and Value
        response.assert_status_is_ok();
    }

    /// Test bad request for creating a token
    #[tokio::test]
    async fn test_get_token_auth_token_bad() {
        // Test JWT keys and User Creds
        let (encoding_key, decoding_key) = gen_test_encode_decode_tokens();
        let user_creds = gen_test_user_creds("test_user");

        // Test Client
        let ep = OpenApiService::new(Api, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .post("/gen_token")
            .header("X-API-Key", "bad_token")
            .data(encoding_key)
            .data(decoding_key)
            .data(user_creds)
            .send()
            .await;

        // Check status and Value
        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    /// Test create domain
    #[sqlx::test]
    async fn test_domain_post(pool: PgPool) {
        // Test JWT keys and User Creds
        let (encoding_key, decoding_key) = gen_test_encode_decode_tokens();
        let user_creds = gen_test_user_creds("test_user");

        // Test JWT
        let token = make_jwt("test_user", &encoding_key).unwrap();

        // Payload to send into the API
        let domain_param = gen_test_domain_parm("test_domain");
        let body = serde_json::to_string(&domain_param).unwrap();

        // Test Client
        let ep = OpenApiService::new(Api, "test", "1.0");
        let cli = TestClient::new(ep);

        // Test Request
        let response = cli
            .post("/domain")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .body(body)
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
        // Test JWT keys and User Creds
        let (encoding_key, decoding_key) = gen_test_encode_decode_tokens();
        let user_creds = gen_test_user_creds("test_user");

        // Test JWT
        let token = make_jwt("test_user", &encoding_key).unwrap();

        // Payload to send into the API
        let domain_param = gen_test_domain_parm("test_domain");
        let body = serde_json::to_string(&domain_param).unwrap();

        // Test Client
        let ep = OpenApiService::new(Api, "test", "1.0");
        let cli = TestClient::new(ep);

        // Create prior record
        {
            let mut tx = pool.begin().await.unwrap();
            domain_add(&mut tx, &domain_param, "test_user")
                .await
                .unwrap();

            tx.commit().await.unwrap();
        }

        // Add conflicting record
        let response = cli
            .post("/domain")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .body(body)
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
        // Payload to send into the API
        let domain_param = gen_test_domain_parm("test_domain");

        // Test Client
        let ep = OpenApiService::new(Api, "test", "1.0");
        let cli = TestClient::new(ep);

        // Create record
        {
            let mut tx = pool.begin().await.unwrap();
            domain_add(&mut tx, &domain_param, "test_user")
                .await
                .unwrap();

            tx.commit().await.unwrap();
        }

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
        let ep = OpenApiService::new(Api, "test", "1.0");
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
        // Test JWT keys and User Creds
        let (encoding_key, decoding_key) = gen_test_encode_decode_tokens();
        let user_creds = gen_test_user_creds("foobar_user");

        // Test JWT
        let token = make_jwt("foobar_user", &encoding_key).unwrap();

        // Payload to send into the API
        let domain_param = gen_test_domain_parm("test_domain");
        let foobar_param = gen_test_domain_parm("foobar_domain");
        let body = serde_json::to_string(&foobar_param).unwrap();

        // Test Client
        let ep = OpenApiService::new(Api, "test", "1.0");
        let cli = TestClient::new(ep);

        // Create prior record
        {
            let mut tx = pool.begin().await.unwrap();
            domain_add(&mut tx, &domain_param, "test_user")
                .await
                .unwrap();

            tx.commit().await.unwrap();
        }

        // Update existing record
        let response = cli
            .put("/domain/test_domain")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .body(body)
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
            .assert_string("foobar_user");
    }

    /// Test domain update where no domain found
    #[sqlx::test]
    async fn test_domain_put_not_found(pool: PgPool) {
        // Test JWT keys and User Creds
        let (encoding_key, decoding_key) = gen_test_encode_decode_tokens();
        let user_creds = gen_test_user_creds("foobar_user");

        // Test JWT
        let token = make_jwt("foobar_user", &encoding_key).unwrap();

        // Payload to send into the API
        let domain_param = gen_test_domain_parm("test_domain");
        let body = serde_json::to_string(&domain_param).unwrap();

        // Test Client
        let ep = OpenApiService::new(Api, "test", "1.0");
        let cli = TestClient::new(ep);

        // Add conflicting record
        let response = cli
            .put("/domain/test_domain")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .body(body)
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
        // Test JWT keys and User Creds
        let (encoding_key, decoding_key) = gen_test_encode_decode_tokens();
        let user_creds = gen_test_user_creds("foobar_user");

        // Test JWT
        let token = make_jwt("foobar_user", &encoding_key).unwrap();

        // Payload to send into the API
        let domain_param = gen_test_domain_parm("test_domain");
        let foobar_param = gen_test_domain_parm("foobar_domain");
        let body = serde_json::to_string(&foobar_param).unwrap();

        // Test Client
        let ep = OpenApiService::new(Api, "test", "1.0");
        let cli = TestClient::new(ep);

        // Create prior records
        {
            let mut tx = pool.begin().await.unwrap();

            domain_add(&mut tx, &domain_param, "test_user")
                .await
                .unwrap();

            domain_add(&mut tx, &foobar_param, "test_user")
                .await
                .unwrap();

            tx.commit().await.unwrap();
        }

        // Update existing record
        let response = cli
            .put("/domain/test_domain")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .body(body)
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
        // Test JWT keys and User Creds
        let (encoding_key, decoding_key) = gen_test_encode_decode_tokens();
        let user_creds = gen_test_user_creds("foobar_user");

        // Test JWT
        let token = make_jwt("foobar_user", &encoding_key).unwrap();

        // Payload to send into the API
        let domain_param = gen_test_domain_parm("test_domain");

        // Test Client
        let ep = OpenApiService::new(Api, "test", "1.0");
        let cli = TestClient::new(ep);

        // Create prior records
        {
            let mut tx = pool.begin().await.unwrap();
            domain_add(&mut tx, &domain_param, "test_user")
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }

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
        let (encoding_key, decoding_key) = gen_test_encode_decode_tokens();
        let user_creds = gen_test_user_creds("foobar_user");

        // Test JWT
        let token = make_jwt("foobar_user", &encoding_key).unwrap();

        // Test Client
        let ep = OpenApiService::new(Api, "test", "1.0");
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
        // Test JWT keys and User Creds
        let (encoding_key, decoding_key) = gen_test_encode_decode_tokens();
        let user_creds = gen_test_user_creds("test_user");

        // Test JWT
        let token = make_jwt("test_user", &encoding_key).unwrap();

        // Payload to send into the API
        let domain_param = gen_test_domain_parm("test_domain");
        let model_param = gen_test_model_parm("test_model", "test_domain");

        // Test Client
        let ep = OpenApiService::new(Api, "test", "1.0");
        let cli = TestClient::new(ep);

        // Create prior records
        {
            let mut tx = pool.begin().await.unwrap();
            domain_add(&mut tx, &domain_param, "test_user")
                .await
                .unwrap();
            model_add(&mut tx, &model_param, "test_user").await.unwrap();
            tx.commit().await.unwrap();
        }

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
}
//TODO Add integration test
