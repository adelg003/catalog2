use crate::{
    util::Tag,
    domain_models::core::{domain_read_with_models, DomainModels},
};
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{param::Path, payload::Json, OpenApi};
use sqlx::PgPool;

/// Struct we will build our REST API / Webserver
pub struct DomainModelsApi;

#[OpenApi]
impl DomainModelsApi {
    /// Get a single domain and its models
    #[oai(path = "/domain_with_models/:domain_name", method = "get", tag = Tag::DomainModels)]
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_utils::{
        gen_jwt_encode_decode_token, gen_test_domain_json, gen_test_model_json,
        gen_test_user_creds, post_test_domain, post_test_model,
    };
    use poem::test::TestClient;
    use poem_openapi::OpenApiService;

    /// Test Reading domain with models
    #[sqlx::test]
    async fn test_domain_get_with_models(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model1", "test_domain");
        post_test_model(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("test_model2", "test_domain");
        post_test_model(&body, &pool).await;

        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(DomainModelsApi, "test", "1.0");
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
