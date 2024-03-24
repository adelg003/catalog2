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
#[derive(Clone, Deserialize)]
pub struct UserCred {
    pub username: String,
    pub hash: String,
}

/// Struct to return when authenticating
#[derive(Debug, Deserialize, Object)]
pub struct User {
    pub username: String,
}

const ONE_HOUR: u64 = 3600;

/// Claim for JWT
#[derive(Deserialize, Serialize)]
pub struct Claim {
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

/// Basic Authentication
#[derive(SecurityScheme)]
#[oai(ty = "basic", checker = "basic_checker")]
pub struct BasicAuth(User);

/// How we authenticate for BasicAuth
async fn basic_checker(req: &Request, basic: Basic) -> Option<User> {
    // Pull approved user creds
    let user_creds = req.data::<Vec<UserCred>>()?;

    // Lets see if any of our creds match
    for user_cred in user_creds {
        if basic.username == user_cred.username {
            let verify_result = verify(&basic.password, &user_cred.hash);

            // Map verify_result to what we want to do with it
            match verify_result {
                Ok(true) => {
                    return Some(User {
                        username: basic.username,
                    })
                }
                Ok(false) => (),
                Err(_) => return None,
            };
        }
    }

    // Well, looks link nothing matches, so rejected
    None
}

/// Key Authentication
#[derive(SecurityScheme)]
#[oai(
    ty = "api_key",
    key_name = "X-API-Key",
    key_in = "header",
    checker = "jwt_checker"
)]
pub struct JwtAuth(User);

/// How JwtAuth validates a token
async fn jwt_checker(req: &Request, api_key: ApiKey) -> Option<User> {
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

/// Authentication for the REST API
#[derive(SecurityScheme)]
pub enum Auth {
    BasicAuth(BasicAuth),
    JwtAuth(JwtAuth),
}

impl Auth {
    /// Pull the username if the user was authenticated
    pub fn username(&self) -> &String {
        // Get user from authentication.
        match self {
            Auth::BasicAuth(auth) => &auth.0.username,
            Auth::JwtAuth(auth) => &auth.0.username,
        }
    }
}
