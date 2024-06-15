use crate::{dependency::DependencyType, graph::core::Edge};
use sqlx::{query_as, Postgres, Transaction};

/// Pull related nodes to the root node
pub async fn edge_select(
    tx: &mut Transaction<'_, Postgres>,
    node_type: &DependencyType,
    node_id: &i32,
    source_distance: &u32,
    dest_distance: &u32,
) -> Result<Vec<Edge>, sqlx::Error> {
    // Query to pull all edges that relate to the node
    query_as!(
        Edge,
        "
        -- Pull Edges link to selected node
        WITH RECURSIVE
            -- Data with all parent / child relationships
            data AS (
                -- Model Dependencies
                SELECT
                    'pack' AS source_type,
                    md.pack_id AS source_id,
                    'model' AS dest_type,
                    md.model_id AS dest_id
                FROM
                    model_dependency md
                UNION ALL
                -- Pack Dependencies
                SELECT
                    'model' AS source_type,
                    pd.model_id AS source_id,
                    'pack' AS dest_type,
                    pd.pack_id AS dest_id
                FROM
                    pack_dependency pd
            ),
            -- Trace parent relationships to source parent
            parent AS (
                SELECT
                    source_type,
                    source_id,
                    1 AS source_distance,
                    dest_type,
                    dest_id,
                    0 AS dest_distance
                FROM
                    data
                WHERE
                    dest_type = $1 -- type param
                    AND dest_id = $2 -- id param
                    AND 1 <= $3 -- parent distance param
                UNION ALL
                SELECT
                    d.source_type,
                    d.source_id,
                    p.source_distance + 1 AS source_distance,
                    d.dest_type,
                    d.dest_id,
                    p.dest_distance + 1 AS dest_distance
                FROM
                    data d
                INNER JOIN
                    parent p
                ON
                    d.dest_type = p.source_type
                    AND d.dest_id = p.source_id
                WHERE
                    p.source_distance + 1 <= $3 -- parent distance param
            ),
            -- Trace child relationships to final child
            child AS (
                SELECT
                    source_type,
                    source_id,
                    0 AS source_distance,
                    dest_type,
                    dest_id,
                    -1 AS dest_distance
                FROM
                    data
                WHERE
                    source_type = $1 -- type param
                    AND source_id = $2 -- id param
                    AND ABS(-1) <= $4 -- child distance param
                UNION ALL
                SELECT
                    d.source_type,
                    d.source_id,
                    c.source_distance - 1 AS source_distance,
                    d.dest_type,
                    d.dest_id,
                    c.dest_distance - 1 AS dest_distance
                FROM
                    data d
                INNER JOIN
                    child c
                ON
                    d.source_type = c.dest_type
                    AND d.source_id = c.dest_id
                WHERE
                    ABS(c.dest_distance - 1) <= $4 -- child distance param
            ),
            -- Trace parent AND child relationships to source node AND final child
            edges AS (
                SELECT
                    source_type,
                    source_id,
                    source_distance,
                    dest_type,
                    dest_id,
                    dest_distance
                FROM
                    parent
                UNION ALL
                SELECT
                    source_type,
                    source_id,
                    source_distance,
                    dest_type,
                    dest_id,
                    dest_distance
                FROM
                    child
            ),
            -- Lets expose some use full details to describe the node
            details AS (
                SELECT
                    'model' AS type,
                    id,
                    name
                FROM
                    model
                UNION ALL
                SELECT
                    'pack' AS type,
                    id,
                    name
                FROM
                    pack
            )
        -- Now we can finally select what we want
        SELECT
            edges.source_type AS \"source_type!: DependencyType\",
            edges.source_id,
            source.name AS source_name,
            edges.dest_type AS \"dest_type!: DependencyType\",
            edges.dest_id,
            dest.name AS dest_name
        FROM
            edges
        LEFT JOIN
            details source
        ON
            source.type = edges.source_type
            AND source.id = edges.source_id
        LEFT JOIN
            details dest
        ON
            dest.type = edges.dest_type
            AND dest.id = edges.dest_id
        ",
        node_type.to_string(),
        node_id,
        *source_distance as i32,
        *dest_distance as i32,
    )
    .fetch_all(&mut **tx)
    .await
}
