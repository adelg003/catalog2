use poem_openapi::Tags;
use regex::Regex;
use validator::ValidationError;

pub const PAGE_SIZE: u64 = 50;

#[derive(Tags)]
pub enum Tag {
    Auth,
    Domain,
    #[oai(rename = "Domain with Children")]
    DomainWithChildren,
    Field,
    Model,
    #[oai(rename = "Model with Fields")]
    ModelWithFields,
    Search,
    Pack,
}

/// Only allow for valid DBX name, meaning letters, number, dashes, and underscores. First
/// character needs to be a letter. Also, since DBX is case-insensitive, only allow lower
/// characters to ensure unique constraints work.
pub fn dbx_validater(obj_name: &str) -> Result<(), ValidationError> {
    let dbx_regex = Regex::new("^[a-z][a-z0-9_-]*$");
    match dbx_regex {
        Ok(re) if re.is_match(obj_name) => Ok(()),
        _ => Err(ValidationError::new("Failed DBX Regex Check")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test DBX Validater
    #[test]
    fn test_dbx_validator() {
        let failed_check = ValidationError::new("Failed DBX Regex Check");

        assert_eq!(dbx_validater("test_abc-123"), Ok(()));
        assert_eq!(dbx_validater("test_&"), Err(failed_check.clone()));
        assert_eq!(dbx_validater("123-test"), Err(failed_check.clone()));
        assert_eq!(dbx_validater(""), Err(failed_check));
    }
}

#[cfg(test)]
pub mod test_utils {
    use crate::{
        auth::{AuthApi, UserCred},
        domain::DomainApi,
        field::FieldApi,
        model::ModelApi,
        pack::PackApi,
    };
    use jsonwebtoken::{DecodingKey, EncodingKey};
    use poem::{test::TestClient, web::headers::Authorization};
    use poem_openapi::OpenApiService;
    use serde_json::json;
    use sqlx::PgPool;

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

    /// Create test model JSON
    pub fn gen_test_model_json(name: &str, domain_name: &str) -> serde_json::Value {
        json!({
            "name": name,
            "domain_name": domain_name,
            "owner": format!("{}@test.com", name),
            "extra": {
                "abc": 123,
                "def": [1, 2, 3],
            },
        })
    }

    /// Create a test model
    pub async fn post_test_model(body: &serde_json::Value, pool: &PgPool) {
        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(ModelApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Create Domain
        let response = cli
            .post("/model")
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

    /// Create test field JSON
    pub fn gen_test_field_json(name: &str, model_name: &str) -> serde_json::Value {
        json!({
            "name": name,
            "model_name": model_name,
            "is_primary": false,
            "data_type": "decimal",
            "is_nullable": true,
            "precision": 8,
            "scale": 2,
            "extra": {
                "abc": 123,
                "def": [1, 2, 3],
            },
        })
    }

    /// Create a test field
    pub async fn post_test_field(body: &serde_json::Value, pool: &PgPool) {
        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(FieldApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Create Domain
        let response = cli
            .post("/field")
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

    /// Create test pack JSON
    pub fn gen_test_pack_json(name: &str, domain_name: &str) -> serde_json::Value {
        json!({
            "name": name,
            "domain_name": domain_name,
            "runtime": "docker",
            "compute": "dbx",
            "repo": "http://test.repo.org",
            "owner": format!("{}@test.com", name),
            "extra": {
                "abc": 123,
                "def": [1, 2, 3],
            },
        })
    }

    /// Create a test pack
    pub async fn post_test_pack(body: &serde_json::Value, pool: &PgPool) {
        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (token, _, decoding_key) = gen_jwt_encode_decode_token(&user_creds).await;

        // Test Client
        let ep = OpenApiService::new(PackApi, "test", "1.0");
        let cli = TestClient::new(ep);

        // Create Domain
        let response = cli
            .post("/pack")
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
}
