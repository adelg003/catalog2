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

const ONE_WEEK: u64 = 60 * 60 * 24 * 7;

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
        exp: get_current_timestamp() + ONE_WEEK,
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

    // Pull user creds
    let user_cred = user_creds
        .iter()
        .find(|user_cred| user_cred.username == basic.username)?;

    // Verify password to hash
    let valid = verify(&basic.password, &user_cred.hash).ok()?;

    // Return user if true, on None if false
    valid.then_some(User {
        username: basic.username,
    })
}

/// Token Authentication
#[derive(SecurityScheme)]
#[oai(
    ty = "api_key",
    key_name = "X-API-Key",
    key_in = "header",
    checker = "token_checker"
)]
pub struct TokenAuth(User);

impl Auth for TokenAuth {
    /// Return username in TokenAuth
    fn username(&self) -> &String {
        &self.0.username
    }
}

/// How JwtAuth validates a token
async fn token_checker(req: &Request, api_key: ApiKey) -> Option<User> {
    // Pull decoding key
    let decoding_key = req.data::<DecodingKey>()?;

    // Pull jwt data
    let token_data = decode::<Claim>(&api_key.key, decoding_key, &Validation::default()).ok()?;

    // Make sure the user in the token is still valid.
    let user_creds = req.data::<Vec<UserCred>>()?;
    user_creds
        .iter()
        .find(|user_cred| user_cred.username == token_data.claims.sub)?;

    // Return User from inside the token
    Some(User {
        username: token_data.claims.sub,
    })
}

/// Key or Basic Auth
#[derive(SecurityScheme)]
pub enum TokenOrBasicAuth {
    TokenAuth(TokenAuth),
    BasicAuth(BasicAuth),
}

impl Auth for TokenOrBasicAuth {
    /// Return username in TokenOrBasicAuth
    fn username(&self) -> &String {
        match self {
            TokenOrBasicAuth::TokenAuth(auth) => auth.username(),
            TokenOrBasicAuth::BasicAuth(auth) => auth.username(),
        }
    }
}
