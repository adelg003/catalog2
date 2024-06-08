use crate::{
    auth::{Auth, TokenAuth},
    dependency::core::{
        dependencies_read, dependencies_remove, dependency_add, dependency_edit, dependency_read,
        dependency_remove, Dependency, DependencyParam, DependencyParamUpdate, DependencyType,
    },
    util::Tag,
};
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{param::Path, payload::Json, OpenApi};
use sqlx::PgPool;

/// Struct we will build our REST API / Webserver
pub struct DependencyApi;

#[OpenApi]
impl DependencyApi {
    /// Add a dependency to the dependency tables
    #[oai(path = "/dependency/:type", method = "post", tag = Tag::Dependency)]
    async fn dependency_post(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(r#type): Path<DependencyType>,
        Json(param): Json<DependencyParam>,
    ) -> Result<Json<Dependency>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Add a dependency for models
        let dependency = dependency_add(&mut tx, &r#type, &param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(dependency))
    }

    /// Get a single dependency by providing a single pack and model. Need to provide what type the
    /// root node is.
    #[oai(path = "/dependency/:type/:root_name/:child_name", method = "get", tag = Tag::Dependency)]
    async fn dependency_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(r#type): Path<DependencyType>,
        Path(root_name): Path<String>,
        Path(child_name): Path<String>,
    ) -> Result<Json<Dependency>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull dependency
        let dependency = match r#type {
            DependencyType::Model => {
                dependency_read(&mut tx, &r#type, &root_name, &child_name).await?
            }
            DependencyType::Pack => {
                dependency_read(&mut tx, &r#type, &child_name, &root_name).await?
            }
        };

        Ok(Json(dependency))
    }

    /// Get a many dependencies for a model or pack
    #[oai(path = "/dependencies/:type/:name", method = "get", tag = Tag::Dependency)]
    async fn dependencies_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(r#type): Path<DependencyType>,
        Path(name): Path<String>,
    ) -> Result<Json<Vec<Dependency>>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull dependency
        let dependencies = dependencies_read(&mut tx, &r#type, &name).await?;

        Ok(Json(dependencies))
    }

    /// Change a dependency by providing a single pack and model. Need to provide what type the
    /// root node is.
    #[oai(path = "/dependency/:type/:root_name/:child_name", method = "put", tag = Tag::Dependency)]
    async fn dependency_put(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(r#type): Path<DependencyType>,
        Path(root_name): Path<String>,
        Path(child_name): Path<String>,
        Json(param): Json<DependencyParamUpdate>,
    ) -> Result<Json<Dependency>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Run Model add logic
        let dependency = match r#type {
            DependencyType::Model => {
                dependency_edit(&mut tx, &r#type, &root_name, &child_name, &param, username).await?
            }
            DependencyType::Pack => {
                dependency_edit(&mut tx, &r#type, &child_name, &root_name, &param, username).await?
            }
        };

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(dependency))
    }

    /// Delete a dependency
    #[oai(path = "/dependency/:type/:root_name/:child_name", method = "delete", tag = Tag::Dependency)]
    async fn dependency_delete(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(r#type): Path<DependencyType>,
        Path(root_name): Path<String>,
        Path(child_name): Path<String>,
    ) -> Result<Json<Dependency>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Delete Model
        let dependency = match r#type {
            DependencyType::Model => {
                dependency_remove(&mut tx, &r#type, &root_name, &child_name).await?
            }
            DependencyType::Pack => {
                dependency_remove(&mut tx, &r#type, &child_name, &root_name).await?
            }
        };

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(dependency))
    }

    /// Delete all dependencies for a model or pack
    #[oai(path = "/dependencies/:type/:name", method = "delete", tag = Tag::Dependency)]
    async fn dependencies_delete(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(r#type): Path<DependencyType>,
        Path(name): Path<String>,
    ) -> Result<Json<Vec<Dependency>>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Delete Model
        let dependencies = dependencies_remove(&mut tx, &r#type, &name).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(dependencies))
    }
}
