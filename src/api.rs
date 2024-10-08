use crate::{
    auth::AuthApi, dependency::DependencyApi, domain::DomainApi, field::FieldApi, graph::GraphApi,
    model::ModelApi, pack::PackApi, schema::SchemaApi,
};
use poem::Route;
use poem_openapi::{OpenApiService, Tags};

#[derive(Tags)]
pub enum Tag {
    Auth,
    Dependency,
    Domain,
    #[oai(rename = "Domain with Children")]
    DomainWithChildren,
    Field,
    Graph,
    Model,
    #[oai(rename = "Model with Children")]
    ModelWithChildren,
    Schema,
    #[oai(rename = "Schema with Fields")]
    SchemaWithFields,
    #[oai(rename = "Schema with Models")]
    SchemaWithModels,
    Search,
    Pack,
    #[oai(rename = "Pack with Children")]
    PackWithChildren,
}

/// Provide routs for the API endpoints
pub fn route(api_url: &str) -> Route {
    // Collect all the APIs into one
    let api_collection = (
        AuthApi,
        DependencyApi,
        DomainApi,
        FieldApi,
        GraphApi,
        ModelApi,
        PackApi,
        SchemaApi,
    );

    // Setup API Endpoints
    let api_service = OpenApiService::new(api_collection, "Catalog2", "0.1.0").server(api_url);

    // Setup OpenAPI Spec
    let spec = api_service.spec_endpoint();

    // Setup Swagger Page
    let swagger = api_service.swagger_ui();

    Route::new()
        .nest("/", api_service)
        .at("/spec", spec)
        .nest("/swagger", swagger)
}
