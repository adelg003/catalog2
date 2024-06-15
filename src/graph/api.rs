use crate::{
    api::Tag,
    dependency::DependencyType,
    graph::core::{graph_dependencies, Dag},
};
use petgraph::dot::{Config, Dot};
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{
    param::{Path, Query},
    payload::Json,
    Object, OpenApi,
};
use sqlx::PgPool;

/// Return format of the graph
#[derive(Object)]
struct DagReturn {
    petgraph: serde_json::Value,
    dot: String,
}

/// Struct we will build our REST API / Webserver
pub struct GraphApi;

#[OpenApi]
impl GraphApi {
    /// Get a graph of all the dependencies for a node
    #[oai(path = "/graph/:node_type/:node_name", method = "get", tag = Tag::Graph)]
    async fn graph_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(node_type): Path<DependencyType>,
        Path(node_name): Path<String>,
        Query(source_distance): Query<Option<u32>>,
        Query(dest_distance): Query<Option<u32>>,
    ) -> Result<Json<DagReturn>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Create the Dependency Graph from the DB
        let dependency_flow: Dag = graph_dependencies(
            &mut tx,
            &node_type,
            &node_name,
            &source_distance,
            &dest_distance,
        )
        .await?;

        // Transform Graph to JSON / DOT friendly formats
        let petgraph: serde_json::Value =
            serde_json::to_value(&dependency_flow).map_err(InternalServerError)?;
        let dot: String = Dot::with_config(&dependency_flow, &[Config::EdgeNoLabel]).to_string();

        Ok(Json(DagReturn { petgraph, dot }))
    }
}
