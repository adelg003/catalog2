mod api;
mod auth;
mod dependency;
mod domain;
mod field;
mod graph;
mod index;
mod model;
mod pack;
mod search;
mod util;

use crate::auth::UserCred;
use color_eyre::eyre;
use jsonwebtoken::{DecodingKey, EncodingKey};
use poem::{
    endpoint::EmbeddedFilesEndpoint,
    listener::TcpListener,
    middleware::Tracing,
    session::{CookieConfig, CookieSession},
    web::cookie::{CookieKey, SameSite},
    EndpointExt, Route, Server,
};
use rust_embed::Embed;
use sqlx::{migrate, PgPool};

/// Static files hosted via the webserver
#[derive(Embed)]
#[folder = "assets"]
struct Assets;

/// Read an environment variable or fall back to .env file
fn read_env_var(env_var: &str) -> Result<String, dotenvy::Error> {
    let var_str = std::env::var(env_var).unwrap_or(dotenvy::var(env_var)?);
    Ok(var_str)
}

#[tokio::main]
async fn main() -> Result<(), eyre::Error> {
    // Lets get pretty error reports
    color_eyre::install()?;

    // Use async-friendly logging for Poem
    tracing_subscriber::fmt()
        .with_env_filter("poem=trace")
        .init();

    // Read the configs from Env Variable and then fall back to the .env file.
    let conn_str: String = read_env_var("DATABASE_URL")?;
    let web_addr: String = read_env_var("WEB_URL")?;
    let user_creds: Vec<UserCred> = serde_json::from_str(&read_env_var("USER_CREDS")?)?;

    // Generate the encoding and decoding keys for JWT and Cookies
    let secert_key = read_env_var("SECERT_KEY")?;
    let secert_key = secert_key.as_bytes();
    let encoding_key = EncodingKey::from_secret(secert_key);
    let decoding_key = DecodingKey::from_secret(secert_key);
    let cookie_key = CookieKey::from(secert_key);
    let cookie_config = CookieConfig::signed(cookie_key).same_site(SameSite::Lax);

    // Connect to DB and upgrade if needed.
    let pool = PgPool::connect(&conn_str).await?;
    migrate!().run(&pool).await?;

    // Route inbound traffic
    let app = Route::new()
        // Developer friendly locations
        .nest("/api", api::route(&format!("http://{web_addr}/api")))
        .nest("/assets", EmbeddedFilesEndpoint::<Assets>::new())
        // User friendly locations
        .at("/", index::route())
        .nest("/auth", auth::route())
        .nest("/domain", domain::route())
        .nest("/search", search::route())
        // Global context to be shared
        .data(pool)
        .data(user_creds)
        .data(encoding_key)
        .data(decoding_key)
        // Utilites being added to our services
        .with(Tracing)
        .with(CookieSession::new(cookie_config));

    // Lets run our service
    Server::new(TcpListener::bind(web_addr)).run(app).await?;

    Ok(())
}
