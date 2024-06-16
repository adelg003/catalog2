use crate::{
    domain::domain_select,
    pack::core::{ComputeType, Pack, PackParam,  RuntimeType},
};
use chrono::Utc;
use sqlx::{query, query_as, Postgres, QueryBuilder, Transaction};

/// Add a pack to the pack table
pub async fn pack_insert(
    tx: &mut Transaction<'_, Postgres>,
    pack_param: &PackParam,
    username: &str,
) -> Result<Pack, sqlx::Error> {
    let domain = domain_select(tx, &pack_param.domain_name).await?;

    query!(
        "INSERT INTO pack (
            name,
            domain_id,
            runtime,
            compute,
            repo,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date
        ) VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            $11
        )",
        pack_param.name,
        domain.id,
        pack_param.runtime as RuntimeType,
        pack_param.compute as ComputeType,
        pack_param.repo,
        pack_param.owner,
        pack_param.extra,
        username,
        Utc::now(),
        username,
        Utc::now(),
    )
    .execute(&mut **tx)
    .await?;

    // Pull the row
    let model = pack_select(tx, &pack_param.name).await?;

    Ok(model)
}

/// Pull one Pack
pub async fn pack_select(
    tx: &mut Transaction<'_, Postgres>,
    pack_name: &str,
) -> Result<Pack, sqlx::Error> {
    let pack = query_as!(
        Pack,
        "SELECT
            pack.id,
            pack.name,
            pack.domain_id,
            domain.name AS \"domain_name\",
            pack.runtime AS \"runtime!: RuntimeType\",
            pack.compute AS \"compute!: ComputeType\",
            pack.repo,
            pack.owner,
            pack.extra,
            pack.created_by,
            pack.created_date,
            pack.modified_by,
            pack.modified_date
        FROM
            pack
        LEFT JOIN
            domain
        ON
            pack.domain_id = domain.id 
        WHERE
            pack.name = $1",
        pack_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(pack)
}

/// Update a pack
pub async fn pack_update(
    tx: &mut Transaction<'_, Postgres>,
    pack_name: &str,
    pack_param: &PackParam,
    username: &str,
) -> Result<Pack, sqlx::Error> {
    // Make sure related domain exists
    let domain = domain_select(tx, &pack_param.domain_name).await?;

    let rows_affected = query!(
        "UPDATE
            pack
        SET 
            name = $1,
            domain_id = $2,
            runtime = $3,
            compute = $4,
            repo = $5,
            owner = $6,
            extra = $7,
            modified_by = $8,
            modified_date = $9
        WHERE
            name = $10",
        pack_param.name,
        domain.id,
        pack_param.runtime as RuntimeType,
        pack_param.compute as ComputeType,
        pack_param.repo,
        pack_param.owner,
        pack_param.extra,
        username,
        Utc::now(),
        pack_name,
    )
    .execute(&mut **tx)
    .await?
    .rows_affected();

    // Check if any rows were updated.
    if rows_affected == 0 {
        return Err(sqlx::Error::RowNotFound);
    }

    // Pull the row, but with the domain name added
    let pack = pack_select(tx, &pack_param.name).await?;

    Ok(pack)
}

/// Delete a pack
pub async fn pack_drop(
    tx: &mut Transaction<'_, Postgres>,
    pack_name: &str,
) -> Result<Pack, sqlx::Error> {
    // Pull the row
    let pack = pack_select(tx, pack_name).await?;

    // Now run the delete since we have the row in memory
    query!(
        "DELETE FROM
            pack
        WHERE
            name = $1",
        pack_name,
    )
    .execute(&mut **tx)
    .await?;

    Ok(pack)
}

#[cfg(test)]
mod tests {

    /// Test create pack
    #[test]
    #[should_panic]
    fn test_pack_insert() {
        todo!();
    }

    /// Test pack insert where no domain found
    #[test]
    #[should_panic]
    fn test_pack_insert_not_found() {
        todo!();
    }

    /// Test double pack create conflict
    #[test]
    #[should_panic]
    fn test_pack_insert_conflict() {
        todo!();
    }

    /// Test pack select
    #[test]
    #[should_panic]
    fn test_pack_select() {
        todo!();
    }

    /// Test Reading a pack that does not exists
    #[test]
    #[should_panic]
    fn test_pack_select_not_found() {
        todo!();
    }


    /// Test pack update
    #[test]
    #[should_panic]
    fn test_pack_update() {
        todo!();
    }

    /// Test pack update where no domain or pack found
    #[test]
    #[should_panic]
    fn test_pack_update_not_found() {
        todo!();
    }

    /// Test pack update with conflict
    #[test]
    #[should_panic]
    fn test_pack_update_conflict() {
        todo!();
    }

    /// Test pack drop
    #[test]
    #[should_panic]
    fn test_pack_drop() {
        todo!();
    }

    /// Test pack drop if not exists
    #[test]
    #[should_panic]
    fn test_pack_drop_not_found() {
        todo!();
    }

    /// Test pack drop if children not droppped
    #[test]
    #[should_panic]
    fn test_pack_drop_conflict() {
        todo!();
    }
}
