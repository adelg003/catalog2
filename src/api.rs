use crate::{
    auth::{Auth, TokenAuth},
    core::{
        domain_read_with_models, field_add, field_edit, field_read, field_remove, model_add,
        model_add_with_fields, model_edit, model_read, model_read_search, model_read_with_fields,
        model_remove, model_remove_with_fields, DomainModels, Field, FieldParam, FieldParamUpdate,
        Model, ModelFields, ModelFieldsParam, ModelParam, ModelSearch,
    },
};
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{
    param::{Path, Query},
    payload::Json,
    OpenApi, Tags,
};
use sqlx::PgPool;

#[derive(Tags)]
pub enum Tag {
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
pub mod tests {
    use super::*;
    use crate::{
        auth::{AuthApi, UserCred},
        domain::DomainApi,
    };
    use jsonwebtoken::{DecodingKey, EncodingKey};
    use poem::{test::TestClient, web::headers::Authorization};
    use poem_openapi::OpenApiService;
    use serde_json::json;

    /// Create test users creds
    pub fn gen_test_user_creds(user: &str) -> Vec<UserCred> {
        // Test user Cred
        vec![UserCred {
            username: user.to_string(),
            hash: "$2b$12$QkHm2JiQg3WILPe0l/8Vqun7UVLqfSBLAzXiKbffGhs11RSqH7bjS".to_string(),
        }]
    }

    /// Create Encode and Decode Keys
    pub fn gen_encode_decode_token() -> (EncodingKey, DecodingKey) {
        // Test JWT secert and keys
        let jwt_key =
            b"N9&YMUGmNpP@dy$At6jv$CEoXRA5hEgNy%C3n4mVKQpDkJoFMZ5VxK#&e&7xrYrC5$nai73GE!dGKqxc";
        let encoding_key = EncodingKey::from_secret(jwt_key);
        let decoding_key = DecodingKey::from_secret(jwt_key);

        (encoding_key, decoding_key)
    }

    /// Create the JWT, encode key, and decode key tokens
    pub async fn gen_jwt_encode_decode_token(
        user_creds: &[UserCred],
    ) -> (String, EncodingKey, DecodingKey) {
        // Test JWT secert and keys
        let (encoding_key, decoding_key) = gen_encode_decode_token();

        // Test Client
        let ep = OpenApiService::new(AuthApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Get JWT
        let response = cli
            .post("/gen_token")
            .typed_header(Authorization::basic("test_user", "abc123"))
            .data(encoding_key.clone())
            .data(user_creds.to_vec())
            .send()
            .await;

        response.assert_status_is_ok();

        let token = response.0.into_body().into_string().await.unwrap();

        (token, encoding_key, decoding_key)
    }

    /// Create test domain JSON
    pub fn gen_test_domain_json(name: &str) -> serde_json::Value {
        json!({
            "name": name,
            "owner": format!("{}@test.com", name),
            "extra": {
                "abc": 123,
                "def": [1, 2, 3],
            },
        })
    }

    /// Create test model
    pub fn gen_test_model_parm(name: &str, domain_name: &str) -> ModelParam {
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

    /// Create a test domain
    pub async fn post_test_domain(body: &serde_json::Value, pool: &PgPool) {
        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(DomainApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Create Domain
        let response = cli
            .post("/domain")
            .header("X-API-Key", &token)
            .header("Content-Type", "application/json; charset=utf-8")
            .body_json(body)
            .data(decoding_key)
            .data(user_creds)
            .data(pool.clone())
            .send()
            .await;

        response.assert_status_is_ok();
    }

    /// Test Reading domain with models
    #[sqlx::test]
    async fn test_domain_get_with_models(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Create prior records
        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model1", "test_domain");
            model_add(&mut tx, &model_param, "test_user").await.unwrap();

            let model_param = gen_test_model_parm("test_model2", "test_domain");
            model_add(&mut tx, &model_param, "test_user").await.unwrap();

            tx.commit().await.unwrap();
        }

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(Api, "test", "1.0");
        let cli = TestClient::new(ep);

        // Get existing record
        let response = cli
            .get("/domain_with_models/test_domain")
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

        let domain_json = json_value.object().get("domain");
        let model1_json = json_value.object().get("models").array().get(0);
        let model2_json = json_value.object().get("models").array().get(1);

        domain_json.object().get("id").assert_i64(1);
        domain_json
            .object()
            .get("name")
            .assert_string("test_domain");
        domain_json
            .object()
            .get("owner")
            .assert_string("test_domain@test.com");
        domain_json
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        domain_json
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        domain_json
            .object()
            .get("created_by")
            .assert_string("test_user");
        domain_json
            .object()
            .get("modified_by")
            .assert_string("test_user");

        model1_json.object().get("id").assert_i64(1);
        model1_json
            .object()
            .get("name")
            .assert_string("test_model1");
        model1_json.object().get("domain_id").assert_i64(1);
        model1_json
            .object()
            .get("domain_name")
            .assert_string("test_domain");
        model1_json
            .object()
            .get("owner")
            .assert_string("test_model1@test.com");
        model1_json
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        model1_json
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        model1_json
            .object()
            .get("created_by")
            .assert_string("test_user");
        model1_json
            .object()
            .get("modified_by")
            .assert_string("test_user");

        model2_json.object().get("id").assert_i64(2);
        model2_json
            .object()
            .get("name")
            .assert_string("test_model2");
        model2_json.object().get("domain_id").assert_i64(1);
        model2_json
            .object()
            .get("domain_name")
            .assert_string("test_domain");
        model2_json
            .object()
            .get("owner")
            .assert_string("test_model2@test.com");
        model2_json
            .object()
            .get("extra")
            .object()
            .get("abc")
            .assert_i64(123);
        model2_json
            .object()
            .get("extra")
            .object()
            .get("def")
            .assert_i64_array(&[1, 2, 3]);
        model2_json
            .object()
            .get("created_by")
            .assert_string("test_user");
        model2_json
            .object()
            .get("modified_by")
            .assert_string("test_user");
    }
}

//TODO Add integration test
