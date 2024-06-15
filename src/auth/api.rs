use crate::{
    api::Tag,
    auth::core::{make_jwt, Auth, TokenOrBasicAuth},
};
use jsonwebtoken::EncodingKey;
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{payload::PlainText, OpenApi};

/// Struct we will build our REST API / Webserver
pub struct AuthApi;

#[OpenApi]
impl AuthApi {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_utils::{gen_encode_decode_token, gen_test_user_creds};
    use poem::{http::StatusCode, test::TestClient, web::headers::Authorization};
    use poem_openapi::OpenApiService;

    /// Test creating a token
    #[tokio::test]
    async fn test_get_token_auth_basic() {
        // Test JWT keys and User Creds
        let user_creds = gen_test_user_creds("test_user");
        let (encoding_key, _) = gen_encode_decode_token();

        // Test Client
        let ep = OpenApiService::new(AuthApi, "test", "1.0");
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
        let user_creds = gen_test_user_creds("test_user");
        let (encoding_key, _) = gen_encode_decode_token();

        // Test Client
        let ep = OpenApiService::new(AuthApi, "test", "1.0");
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
        let user_creds = gen_test_user_creds("test_user");
        let (encoding_key, decoding_key) = gen_encode_decode_token();

        // Test JWT
        let token = make_jwt("test_user", &encoding_key).unwrap();

        // Test Client
        let ep = OpenApiService::new(AuthApi, "test", "1.0");
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
        let user_creds = gen_test_user_creds("test_user");
        let (encoding_key, decoding_key) = gen_encode_decode_token();

        // Test Client
        let ep = OpenApiService::new(AuthApi, "test", "1.0");
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
}
