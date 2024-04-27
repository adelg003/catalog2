mod api;
mod auth;
mod core;
mod db;
mod domain;
mod domain_models;
mod field;
mod model;
mod util;

use crate::{
    api::Api,
    auth::{AuthApi, UserCred},
    domain::DomainApi,
    domain_models::DomainModelsApi,
    field::FieldApi,
    model::ModelApi,
};
use color_eyre::eyre;
use jsonwebtoken::{DecodingKey, EncodingKey};
use poem::{listener::TcpListener, middleware::Tracing, EndpointExt, Route, Server};
use poem_openapi::OpenApiService;
use sqlx::{migrate, PgPool};

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
    let conn_str = read_env_var("DATABASE_URL")?;
    let web_addr_str = read_env_var("WEB_URL")?;
    let user_creds: Vec<UserCred> = serde_json::from_str(&read_env_var("USER_CREDS")?)?;

    // Generate the encoding and decoding JWT keys
    let jwt_key = read_env_var("JWT_KEY")?;
    let jwt_key = jwt_key.as_bytes();
    let encoding_key = EncodingKey::from_secret(jwt_key);
    let decoding_key = DecodingKey::from_secret(jwt_key);

    // Connect to DB and upgrade if needed.
    let pool = PgPool::connect(&conn_str).await?;
    migrate!().run(&pool).await?;

    // Collect all the APIs into one
    let apis = (Api, AuthApi, DomainApi, DomainModelsApi, ModelApi, FieldApi);

    // Setup OpenAPI Swagger Page
    // TODO - Remove raw API
    let api_service = OpenApiService::new(apis, "Catalog2", "0.1.0")
        .server(format!("http://{}/api", web_addr_str));
    let spec = api_service.spec_endpoint();
    let swagger = api_service.swagger_ui();

    // Route inbound traffic
    let route = Route::new()
        // Developer friendly locations
        .nest("/api", api_service)
        .at("/spec", spec)
        .nest("/swagger", swagger)
        // User friendly locations
        //.at("/", index)
        // Global context to be shared
        .data(pool)
        .data(user_creds)
        .data(encoding_key)
        .data(decoding_key)
        // Utilites being added to our services
        .with(Tracing);

    // Lets run our service
    Server::new(TcpListener::bind(web_addr_str))
        .run(route)
        .await?;

    Ok(())
}
