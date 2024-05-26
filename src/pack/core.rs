use crate::{
    pack::db::{pack_drop, pack_insert, pack_select, pack_select_search, pack_update},
    util::{dbx_validater, PAGE_SIZE},
};
use chrono::{DateTime, Utc};
use poem::{
    error::{BadRequest, Conflict, InternalServerError, NotFound},
    http::StatusCode,
};
use poem_openapi::{Enum, Object};
use sqlx::{FromRow, Postgres, Transaction, Type};
use std::fmt;
use validator::Validate;

/// Runtime the pack will run on.
#[derive(Clone, Copy, Debug, Enum, PartialEq, Type)]
#[oai(rename_all = "lowercase")]
#[sqlx(type_name = "runtime_type", rename_all = "lowercase")]
pub enum RuntimeType {
    Docker,
    DbxJob,
    Dbt,
    Dag,
}

// Needed for SQL builder to use RuntimeType
impl fmt::Display for RuntimeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            RuntimeType::Docker => write!(f, "docker"),
            RuntimeType::DbxJob => write!(f, "dbxjob"),
            RuntimeType::Dbt => write!(f, "dbt"),
            RuntimeType::Dag => write!(f, "dag"),
        }
    }
}

/// Which compute will the runtime / pack use.
#[derive(Clone, Copy, Debug, Enum, PartialEq, Type)]
#[oai(rename_all = "lowercase")]
#[sqlx(type_name = "compute_type", rename_all = "lowercase")]
pub enum ComputeType {
    Docker,
    Dbx,
    Memsql,
}

// Needed for SQL builder to use ComputeType
impl fmt::Display for ComputeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            ComputeType::Docker => write!(f, "docker"),
            ComputeType::Dbx => write!(f, "dbt"),
            ComputeType::Memsql => write!(f, "memsql"),
        }
    }
}

/// Pack to return via the API
#[derive(Debug, FromRow, Object)]
pub struct Pack {
    pub id: i32,
    pub name: String,
    pub domain_id: i32,
    pub domain_name: String,
    pub runtime: RuntimeType,
    pub compute: ComputeType,
    pub repo: String,
    pub owner: String,
    pub extra: serde_json::Value,
    pub created_by: String,
    pub created_date: DateTime<Utc>,
    pub modified_by: String,
    pub modified_date: DateTime<Utc>,
}

/// How to create or update a Pack
#[derive(Debug, Object, Validate)]
pub struct PackParam {
    #[validate(custom(function = dbx_validater))]
    pub name: String,
    pub domain_name: String,
    pub runtime: RuntimeType,
    pub compute: ComputeType,
    #[validate(url)]
    pub repo: String,
    #[validate(email)]
    pub owner: String,
    pub extra: serde_json::Value,
}

/// Pack Search Results
#[derive(Object)]
pub struct PackSearch {
    packs: Vec<Pack>,
    page: u64,
    more: bool,
}

/// Params for searching for packs
pub struct PackSearchParam {
    pub pack_name: Option<String>,
    pub domain_name: Option<String>,
    pub runtime: Option<RuntimeType>,
    pub compute: Option<ComputeType>,
    pub repo: Option<String>,
    pub owner: Option<String>,
    pub extra: Option<String>,
}

/// Add a pack
pub async fn pack_add(
    tx: &mut Transaction<'_, Postgres>,
    pack_param: &PackParam,
    username: &str,
) -> Result<Pack, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    pack_param.validate().map_err(BadRequest)?;

    // Add Pack
    let insert = pack_insert(tx, pack_param, username).await;

    // What result did we get?
    match insert {
        Ok(pack) => Ok(pack),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }
}

/// Read details of a pack
pub async fn pack_read(
    tx: &mut Transaction<'_, Postgres>,
    pack_name: &str,
) -> Result<Pack, poem::Error> {
    // Pull Pack
    pack_select(tx, pack_name).await.map_err(NotFound)
}

/// Read details of many packs
pub async fn pack_read_search(
    tx: &mut Transaction<'_, Postgres>,
    search_param: &PackSearchParam,
    page: &u64,
) -> Result<PackSearch, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;
    let next_offset = (page + 1) * PAGE_SIZE;

    // Pull the Pack
    let packs = pack_select_search(tx, search_param, &Some(PAGE_SIZE), &Some(offset))
        .await
        .map_err(InternalServerError)?;

    // More packs present?
    let next_pack = pack_select_search(tx, search_param, &Some(PAGE_SIZE), &Some(next_offset))
        .await
        .map_err(InternalServerError)?;

    let more = !next_pack.is_empty();

    Ok(PackSearch {
        packs,
        page: *page,
        more,
    })
}
/// Edit a Pack
pub async fn pack_edit(
    tx: &mut Transaction<'_, Postgres>,
    pack_name: &str,
    pack_param: &PackParam,
    username: &str,
) -> Result<Pack, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    pack_param.validate().map_err(BadRequest)?;

    // Update domain
    let update = pack_update(tx, pack_name, pack_param, username).await;

    // What result did we get?
    match update {
        Ok(pack) => Ok(pack),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain or pack does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }
}

/// Remove a Pack
pub async fn pack_remove(
    tx: &mut Transaction<'_, Postgres>,
    pack_name: &str,
) -> Result<Pack, poem::Error> {
    // Delete the pack
    let delete = pack_drop(tx, pack_name).await;

    // What result did we get?
    match delete {
        Ok(pack) => Ok(pack),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "pack does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }
}

#[cfg(test)]
mod tests {

    /// Test create pack
    #[test]
    #[should_panic]
    fn test_pack_add() {
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
    fn test_pack_read() {
        todo!();
    }

    /// Test Reading a pack that does not exists
    #[test]
    #[should_panic]
    fn test_pack_read_not_found() {
        todo!();
    }

    /// Test pack search
    #[test]
    #[should_panic]
    fn test_pack_read_search() {
        todo!();
    }

    /// Test pack update
    #[test]
    #[should_panic]
    fn test_pack_edit() {
        todo!();
    }

    /// Test pack update where no domain or pack found
    #[test]
    #[should_panic]
    fn test_pack_edit_not_found() {
        todo!();
    }

    /// Test pack update with conflict
    #[test]
    #[should_panic]
    fn test_pack_edit_conflict() {
        todo!();
    }

    /// Test pack drop
    #[test]
    #[should_panic]
    fn test_pack_remove() {
        todo!();
    }

    /// Test pack drop if not exists
    #[test]
    #[should_panic]
    fn test_pack_remove_not_found() {
        todo!();
    }

    /// Test pack drop if children not droppped
    #[test]
    #[should_panic]
    fn test_pack_remove_conflict() {
        todo!();
    }
}
