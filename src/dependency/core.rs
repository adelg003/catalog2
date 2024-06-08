use crate::dependency::db::{
    dependencies_drop, dependencies_select, dependency_drop, dependency_insert, dependency_select,
    dependency_update,
};
use chrono::{DateTime, Utc};
use poem::{
    error::{Conflict, InternalServerError, NotFound},
    http::StatusCode,
};
use poem_openapi::{Enum, Object};
use serde::Serialize;
use sqlx::{FromRow, Postgres, Transaction, Type};
use std::fmt;

/// What kind of dependency are we working with?
#[derive(Clone, Copy, Debug, Enum, PartialEq, Serialize, Type)]
#[oai(rename_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
pub enum DependencyType {
    Model,
    Pack,
}

/// Make DependencyType convertable to a string
impl fmt::Display for DependencyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DependencyType::Model => write!(f, "model"),
            DependencyType::Pack => write!(f, "pack"),
        }
    }
}

/// Model Dependency to return via the API
#[derive(Debug, FromRow, Object)]
pub struct Dependency {
    pub id: i32,
    pub model_id: i32,
    pub model_name: String,
    pub pack_id: i32,
    pub pack_name: String,
    pub extra: serde_json::Value,
    pub created_by: String,
    pub created_date: DateTime<Utc>,
    pub modified_by: String,
    pub modified_date: DateTime<Utc>,
}

/// How to add a new dependency to a model
#[derive(Debug, Object, Serialize)]
pub struct DependencyParam {
    pub model_name: String,
    pub pack_name: String,
    pub extra: serde_json::Value,
}

/// How to update an existing model dependency
#[derive(Object)]
pub struct DependencyParamUpdate {
    pub extra: serde_json::Value,
}

/// Add a dependency
pub async fn dependency_add(
    tx: &mut Transaction<'_, Postgres>,
    dependency_type: &DependencyType,
    param: &DependencyParam,
    username: &str,
) -> Result<Dependency, poem::Error> {
    // Add Dependency
    let insert = dependency_insert(tx, dependency_type, param, username).await;

    // What result did we get?
    match insert {
        Ok(dependency) => Ok(dependency),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "model or pack does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }
}

/// Read details of a dependency
pub async fn dependency_read(
    tx: &mut Transaction<'_, Postgres>,
    dependency_type: &DependencyType,
    model_name: &str,
    pack_name: &str,
) -> Result<Dependency, poem::Error> {
    // Pull dependency
    dependency_select(tx, dependency_type, model_name, pack_name)
        .await
        .map_err(NotFound)
}

/// Read dependencies for a model or pack
pub async fn dependencies_read(
    tx: &mut Transaction<'_, Postgres>,
    dependency_type: &DependencyType,
    name: &str,
) -> Result<Vec<Dependency>, poem::Error> {
    // Pull many dependencies
    dependencies_select(tx, dependency_type, name)
        .await
        .map_err(InternalServerError)
}

/// Edit a Dependency
pub async fn dependency_edit(
    tx: &mut Transaction<'_, Postgres>,
    dependency_type: &DependencyType,
    model_name: &str,
    pack_name: &str,
    param: &DependencyParamUpdate,
    username: &str,
) -> Result<Dependency, poem::Error> {
    // Update dependency
    dependency_update(tx, dependency_type, model_name, pack_name, param, username)
        .await
        .map_err(NotFound)
}

/// Remove a Dependency
pub async fn dependency_remove(
    tx: &mut Transaction<'_, Postgres>,
    dependency_type: &DependencyType,
    model_name: &str,
    pack_name: &str,
) -> Result<Dependency, poem::Error> {
    // Delete the dependency
    dependency_drop(tx, dependency_type, model_name, pack_name)
        .await
        .map_err(NotFound)
}

/// Remove many Dependency for a model or pack
pub async fn dependencies_remove(
    tx: &mut Transaction<'_, Postgres>,
    dependency_type: &DependencyType,
    name: &str,
) -> Result<Vec<Dependency>, poem::Error> {
    // Delete many dependency
    dependencies_drop(tx, dependency_type, name)
        .await
        .map_err(InternalServerError)
}
