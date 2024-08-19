use crate::{
    api::Tag,
    dependency::DependencyType,
    graph::core::{graph_many_node_dependencies, graph_node_dependencies, Dag},
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
    #[oai(path = "/graph_node/:node_type/:node_name", method = "get", tag = Tag::Graph)]
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
        let dag: Dag = graph_node_dependencies(
            &mut tx,
            &node_type,
            &node_name,
            &source_distance,
            &dest_distance,
        )
        .await?;

        // Transform Graph to JSON / DOT friendly formats
        let petgraph: serde_json::Value =
            serde_json::to_value(&dag).map_err(InternalServerError)?;
        let dot: String = Dot::with_config(&dag, &[Config::EdgeNoLabel]).to_string();

        Ok(Json(DagReturn { petgraph, dot }))
    }

    /// Get a graph of all the dependencies for multiple nodes
    #[oai(path = "/graph_many_nodes/:node_type", method = "get", tag = Tag::Graph)]
    async fn graph_multiple_node_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(node_type): Path<DependencyType>,
        Query(node_names): Query<Vec<String>>,
        Query(source_distance): Query<Option<u32>>,
        Query(dest_distance): Query<Option<u32>>,
    ) -> Result<Json<DagReturn>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Create the Dependency Graph from the DB
        let dag: Dag = graph_many_node_dependencies(
            &mut tx,
            &node_type,
            &node_names,
            &source_distance,
            &dest_distance,
        )
        .await?;

        // Transform Graph to JSON / DOT friendly formats
        let petgraph: serde_json::Value =
            serde_json::to_value(&dag).map_err(InternalServerError)?;
        let dot: String = Dot::with_config(&dag, &[Config::EdgeNoLabel]).to_string();

        Ok(Json(DagReturn { petgraph, dot }))
    }
}
