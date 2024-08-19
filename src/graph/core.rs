use crate::{
    dependency::DependencyType, graph::db::edge_select, model::model_read, pack::pack_read,
};
use petgraph::{algo::is_cyclic_directed, prelude::NodeIndex, Directed, Graph};
use poem::{error::InternalServerError, http::StatusCode};
use serde::Serialize;
use sqlx::{FromRow, Postgres, Transaction};
use std::fmt;

/// Nodes that will make up our graph response
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Node {
    r#type: DependencyType,
    id: i32,
    name: String,
}

/// Make DependencyType convertible to a string
impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.r#type, self.name)
    }
}

pub type Dag = Graph<Node, u8, Directed>;

/// Model to returned from the DB
#[derive(FromRow)]
pub struct Edge {
    pub source_type: DependencyType,
    pub source_id: Option<i32>,
    pub source_name: Option<String>,
    pub dest_type: DependencyType,
    pub dest_id: Option<i32>,
    pub dest_name: Option<String>,
}

impl Edge {
    /// Provide the Source Node
    pub fn source_node(&self) -> Node {
        Node {
            r#type: self.source_type,
            id: self.source_id.unwrap_or(-1),
            name: self
                .source_name
                .clone()
                .unwrap_or("INVALID NODE".to_string()),
        }
    }

    /// Provide the Destination Node
    pub fn dest_node(&self) -> Node {
        Node {
            r#type: self.dest_type,
            id: self.dest_id.unwrap_or(-1),
            name: self.dest_name.clone().unwrap_or("INVALID NODE".to_string()),
        }
    }
}

const DISTANCE_MAX: u32 = 100;

/// Build the dependency graph for a single node
pub async fn graph_node_dependencies(
    tx: &mut Transaction<'_, Postgres>,
    node_type: &DependencyType,
    node_name: &str,
    source_distance: &Option<u32>,
    dest_distance: &Option<u32>,
) -> Result<Dag, poem::Error> {
    // Unwrap distance limits
    let source_distance = source_distance.unwrap_or(DISTANCE_MAX);
    let dest_distance = dest_distance.unwrap_or(DISTANCE_MAX);

    // Validate payload
    if source_distance > DISTANCE_MAX || dest_distance > DISTANCE_MAX {
        return Err(poem::Error::from_string(
            format!("Distance provided exceeds the limit of {}", DISTANCE_MAX),
            StatusCode::BAD_REQUEST,
        ));
    }

    // Pull root model / pack id via it type and name
    let node_id: i32 = match node_type {
        DependencyType::Model => model_read(tx, node_name).await?.id,
        DependencyType::Pack => pack_read(tx, node_name).await?.id,
    };

    // Edges of the graph
    let edges: Vec<Edge> = edge_select(tx, node_type, &node_id, &source_distance, &dest_distance)
        .await
        .map_err(InternalServerError)?;

    // Isolate build graph logic to limit mutability
    let dag: Dag = {
        // Graph we will be working with
        let mut dag: Dag = Graph::new();

        // Add root node
        dag.add_node(Node {
            r#type: *node_type,
            id: node_id,
            name: node_name.to_string(),
        });

        // Add edges
        edges.iter().for_each(|edge: &Edge| {
            // Get Nodes
            let source_node: Node = edge.source_node();
            let dest_node: Node = edge.dest_node();

            // Search to see if node already exists. If not, add new node.
            let source_index: NodeIndex = upsert_node(&mut dag, &source_node);
            let dest_index: NodeIndex = upsert_node(&mut dag, &dest_node);

            // Add edge
            dag.update_edge(source_index, dest_index, 1);
        });

        dag
    };

    // Is our dag really a dag? If not, raise error
    match is_cyclic_directed(&dag) {
        false => Ok(dag),
        true => Err(poem::Error::from_string(
            "Dependency flow is cyclical and cannot be rendered as a DAG",
            StatusCode::UNPROCESSABLE_ENTITY,
        )),
    }
}

/// Build the dependency graph for multiple nodes
pub async fn graph_many_node_dependencies(
    tx: &mut Transaction<'_, Postgres>,
    node_type: &DependencyType,
    node_names: &[String],
    source_distance: &Option<u32>,
    dest_distance: &Option<u32>,
) -> Result<Dag, poem::Error> {
    // Collect dag per node
    let dags: Vec<Dag> = {
        let mut dags: Vec<Dag> = Vec::new();

        for node_name in node_names {
            let dag: Dag =
                graph_node_dependencies(tx, node_type, node_name, source_distance, dest_distance)
                    .await?;

            dags.push(dag);
        }
        dags
    };

    // Combine all the Dag Graphs into one
    let dag: Dag = {
        // Working dag we will copy all nodes and edges to
        let mut dag: Dag = Graph::new();

        // Append the nodes and edges for each dag to the output dag
        dags.iter().for_each(|working_dag: &Dag| {
            graph_append(&mut dag, working_dag);
        });

        dag
    };

    Ok(dag)
}

/// Search to see if node already exists. If not, add new node.
fn upsert_node(dag: &mut Dag, node: &Node) -> NodeIndex {
    dag.node_indices()
        .find(|index| &dag[*index] == node)
        .unwrap_or_else(|| dag.add_node(node.clone()))
}

/// Append all the nodes and edges of a graph to a different graph. If matching nodes / edges, do
/// not duplicate the node / edges
fn graph_append(main_dag: &mut Dag, append_dag: &Dag) {
    // Append all the nodes to the main dag
    append_dag.raw_nodes().iter().for_each(|raw_node| {
        upsert_node(main_dag, &raw_node.weight);
    });

    // Append all the edges to the main dag
    append_dag.raw_edges().iter().for_each(|raw_edge| {
        // With the location in the append_dag, pull the node value
        let source_node: &Node = &append_dag[raw_edge.source()];
        let dest_node: &Node = &append_dag[raw_edge.target()];

        // Find the location of the node value in the main_dag
        let source_index: NodeIndex = upsert_node(main_dag, source_node);
        let dest_index: NodeIndex = upsert_node(main_dag, dest_node);

        // Add the new edge with the index addressed for the main_dag and not the append_dag
        main_dag.update_edge(source_index, dest_index, 1);
    });
}
