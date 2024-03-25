use bcrypt::verify;
use jsonwebtoken::{
    decode, encode, get_current_timestamp, DecodingKey, EncodingKey, Header, Validation,
};
use poem::Request;
use poem_openapi::{
    auth::{ApiKey, Basic},
    Object, SecurityScheme,
};
use serde::{Deserialize, Serialize};

/// Struct to hold user creds
#[derive(Clone, Debug, Deserialize)]
pub struct UserCred {
    username: String,
    hash: String,
}

/// Struct to return when authenticating
#[derive(Debug, Object)]
struct User {
    username: String,
}

const ONE_HOUR: u64 = 3600;

/// Claim for JWT
#[derive(Deserialize, Serialize)]
struct Claim {
    sub: String,
    iat: u64,
    exp: u64,
    iss: String,
}

/// Create a new JWT
pub fn make_jwt(
    username: &str,
    encoding_key: &EncodingKey,
) -> Result<String, jsonwebtoken::errors::Error> {
    // Claims for the JWT
    let claim = Claim {
        sub: username.to_string(),
        iat: get_current_timestamp(),
        exp: get_current_timestamp() + ONE_HOUR,
        iss: "Catalog2".to_string(),
    };

    // Generate the JWT
    let token = encode(&Header::default(), &claim, encoding_key)?;
    Ok(token)
}

/// Trait for our auth methoids
pub trait Auth {
    /// All auth methods need to be able to return usernames
    fn username(&self) -> &String;
}

/// Basic Authentication
#[derive(SecurityScheme)]
#[oai(ty = "basic", checker = "basic_checker")]
pub struct BasicAuth(User);

impl Auth for BasicAuth {
    /// Return useername in BasicAuth
    fn username(&self) -> &String {
        &self.0.username
    }
}

/// How we authenticate for BasicAuth
async fn basic_checker(req: &Request, basic: Basic) -> Option<User> {
    // Pull approved user creds
    let user_creds = req.data::<Vec<UserCred>>()?;

    // Pull password hash for username
    let hash = user_creds
        .iter()
        .filter(|user_cred| user_cred.username == basic.username)
        .map(|user_cred| &user_cred.hash)
        .next()?;

    // Verify password to hash
    match verify(&basic.password, hash) {
        // Password matched hash
        Ok(true) => Some(User {
            username: basic.username,
        }),
        // Password did not match hash
        Ok(false) => None,
        // Hmm, looks like the password hash in the config is bad
        Err(_) => unreachable!(
            "Password hash in configs is invalid for user: `{}`",
            &basic.username
        ),
    }
}

/// Key Authentication
#[derive(SecurityScheme)]
#[oai(
    ty = "api_key",
    key_name = "X-API-Key",
    key_in = "header",
    checker = "token_checker"
)]
pub struct TokenAuth(User);

impl Auth for TokenAuth {
    /// Return useername in BasicAuth
    fn username(&self) -> &String {
        &self.0.username
    }
}

/// How JwtAuth validates a token
async fn token_checker(req: &Request, api_key: ApiKey) -> Option<User> {
    // Pull decoding key
    let decoding_key = req.data::<DecodingKey>()?;

    // Pull jwt data
    let decode_result = decode::<Claim>(&api_key.key, decoding_key, &Validation::default());

    // Map decode_result to what we want to do with it
    match decode_result {
        Ok(token_data) => Some(User {
            username: token_data.claims.sub,
        }),
        Err(_) => None,
    }
}
