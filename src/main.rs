mod api;

use crate::api::Api;
use color_eyre::eyre;
use poem::{
    endpoint::StaticFilesEndpoint, listener::TcpListener, middleware::Tracing, EndpointExt, Route,
    Server,
};
use poem_openapi::OpenApiService;
use sqlx::{migrate, PgPool};

#[tokio::main]
async fn main() -> Result<(), eyre::Error> {
    // Lets get pretty error reports
    color_eyre::install()?;

    // Use async-friendly logging for Poem
    tracing_subscriber::fmt()
        .with_env_filter("poem=trace")
        .init();

    // Read the configs from Env Variable and then fall back to the .env file.
    let conn_env_var = "DATABASE_URL";
    let conn_str = std::env::var(conn_env_var).unwrap_or(dotenvy::var(conn_env_var)?);
    let web_addr_env_var = "WEB_URL";
    let web_addr_str = std::env::var(web_addr_env_var).unwrap_or(dotenvy::var(web_addr_env_var)?);

    // Connect to DB and upgrade if needed.
    let pool = PgPool::connect(&conn_str).await?;
    migrate!().run(&pool).await?;

    // Setup OpenAPI Swagger Page
    let api_service = OpenApiService::new(Api, "Catalog2", "0.1.0")
        .server(format!("http://{}/api", web_addr_str));
    let spec = api_service.spec_endpoint();
    let swagger = api_service.swagger_ui();

    // Expose static files
    let assets = StaticFilesEndpoint::new("./assets").show_files_listing();

    // Route inbound traffic
    let route = Route::new()
        // Developer friendly locations
        .nest("/api", api_service)
        .nest("/assets", assets)
        .at("/spec", spec)
        .nest("/swagger", swagger)
        // User friendly locations
        //.at("/", index)
        // Global context to be shared
        .data(pool)
        // Utilites being added to our services
        .with(Tracing);

    // Lets run our service
    Server::new(TcpListener::bind(web_addr_str))
        .run(route)
        .await?;

    Ok(())
}
