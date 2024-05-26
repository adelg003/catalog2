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
    /// Add a dependency to the dependency table
    async fn dependency_post(
        &self,
        auth: &TokenAuth,
        pool: &PgPool,
        dependency_type: &DependencyType,
        param: &DependencyParam,
    ) -> Result<Json<Dependency>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Add a dependency for models
        let dependency = dependency_add(&mut tx, dependency_type, param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(dependency))
    }

    /// Add a model dependency to the model dependency table
    #[oai(path = "/model_dependency", method = "post", tag = Tag::Dependency)]
    async fn model_dependency_post(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Json(param): Json<DependencyParam>,
    ) -> Result<Json<Dependency>, poem::Error> {
        self.dependency_post(&auth, pool, &DependencyType::Model, &param)
            .await
    }

    /// Add a model dependency to the pack dependency table
    #[oai(path = "/pack_dependency", method = "post", tag = Tag::Dependency)]
    async fn pack_dependency_post(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Json(param): Json<DependencyParam>,
    ) -> Result<Json<Dependency>, poem::Error> {
        self.dependency_post(&auth, pool, &DependencyType::Pack, &param)
            .await
    }

    /// Get a single dependency
    async fn dependency_get(
        &self,
        pool: &PgPool,
        dependency_type: &DependencyType,
        model_name: &str,
        pack_name: &str,
    ) -> Result<Json<Dependency>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull dependency
        let dependency = dependency_read(&mut tx, dependency_type, model_name, pack_name).await?;

        Ok(Json(dependency))
    }

    /// Get a single dependency for a model
    #[oai(path = "/model_dependency/:model_name/:pack_name", method = "get", tag = Tag::Dependency)]
    async fn model_dependency_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
        Path(pack_name): Path<String>,
    ) -> Result<Json<Dependency>, poem::Error> {
        self.dependency_get(pool, &DependencyType::Model, &model_name, &pack_name)
            .await
    }

    /// Get a single dependency for a pack
    #[oai(path = "/pack_dependency/:pack_name/:model_name", method = "get", tag = Tag::Dependency)]
    async fn pack_dependency_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
        Path(pack_name): Path<String>,
    ) -> Result<Json<Dependency>, poem::Error> {
        self.dependency_get(pool, &DependencyType::Pack, &model_name, &pack_name)
            .await
    }

    /// Get a many dependencies
    async fn dependencies_get(
        &self,
        pool: &PgPool,
        dependency_type: &DependencyType,
        name: &str,
    ) -> Result<Json<Vec<Dependency>>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull dependency
        let dependencies = dependencies_read(&mut tx, dependency_type, name).await?;

        Ok(Json(dependencies))
    }

    /// Get all dependencies for a model
    #[oai(path = "/model_dependencies/:model_name", method = "get", tag = Tag::Dependency)]
    async fn model_dependencies_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
    ) -> Result<Json<Vec<Dependency>>, poem::Error> {
        self.dependencies_get(pool, &DependencyType::Model, &model_name)
            .await
    }

    /// Get all dependencies for a pack
    #[oai(path = "/pack_dependencies/:pack_name", method = "get", tag = Tag::Dependency)]
    async fn pack_dependencies_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(pack_name): Path<String>,
    ) -> Result<Json<Vec<Dependency>>, poem::Error> {
        self.dependencies_get(pool, &DependencyType::Pack, &pack_name)
            .await
    }

    /// Change a dependency
    async fn dependency_put(
        &self,
        auth: &TokenAuth,
        pool: &PgPool,
        dependency_type: &DependencyType,
        model_name: &str,
        pack_name: &str,
        param: &DependencyParamUpdate,
    ) -> Result<Json<Dependency>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Run Model add logic
        let dependency = dependency_edit(
            &mut tx,
            dependency_type,
            model_name,
            pack_name,
            param,
            username,
        )
        .await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(dependency))
    }

    /// Change a dependency for a model
    #[oai(path = "/model_dependency/:model_name/:pack_name", method = "put", tag = Tag::Dependency)]
    async fn model_dependency_put(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
        Path(pack_name): Path<String>,
        Json(param): Json<DependencyParamUpdate>,
    ) -> Result<Json<Dependency>, poem::Error> {
        self.dependency_put(
            &auth,
            pool,
            &DependencyType::Model,
            &model_name,
            &pack_name,
            &param,
        )
        .await
    }

    /// Change a dependency for a pack
    #[oai(path = "/pack_dependency/:pack_name/:model_name", method = "put", tag = Tag::Dependency)]
    async fn pack_dependency_put(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(pack_name): Path<String>,
        Path(model_name): Path<String>,
        Json(param): Json<DependencyParamUpdate>,
    ) -> Result<Json<Dependency>, poem::Error> {
        self.dependency_put(
            &auth,
            pool,
            &DependencyType::Model,
            &model_name,
            &pack_name,
            &param,
        )
        .await
    }

    /// Delete a dependency
    async fn dependency_delete(
        &self,
        pool: &PgPool,
        dependency_type: &DependencyType,
        model_name: &str,
        pack_name: &str,
    ) -> Result<Json<Dependency>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Delete Model
        let dependency = dependency_remove(&mut tx, dependency_type, model_name, pack_name).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(dependency))
    }

    /// Delete a dependency for a model
    #[oai(path = "/model_dependency/:model_name/:pack_name", method = "delete", tag = Tag::Dependency)]
    async fn model_dependency_delete(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
        Path(pack_name): Path<String>,
    ) -> Result<Json<Dependency>, poem::Error> {
        self.dependency_delete(pool, &DependencyType::Model, &model_name, &pack_name)
            .await
    }

    /// Delete a dependency for a pack
    #[oai(path = "/pack_dependency/:pack_name/:model_name", method = "delete", tag = Tag::Dependency)]
    async fn pack_dependency_delete(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
        Path(pack_name): Path<String>,
    ) -> Result<Json<Dependency>, poem::Error> {
        self.dependency_delete(pool, &DependencyType::Pack, &model_name, &pack_name)
            .await
    }

    /// Delete all dependencies for a model or pack
    async fn dependencies_delete(
        &self,
        pool: &PgPool,
        dependency_type: &DependencyType,
        name: &str,
    ) -> Result<Json<Vec<Dependency>>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Delete Model
        let dependencies = dependencies_remove(&mut tx, dependency_type, name).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(dependencies))
    }

    /// Delete all dependencies for a model
    #[oai(path = "/model_dependencies/:model_name", method = "delete", tag = Tag::Dependency)]
    async fn model_dependencies_delete(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(model_name): Path<String>,
    ) -> Result<Json<Vec<Dependency>>, poem::Error> {
        self.dependencies_delete(pool, &DependencyType::Model, &model_name)
            .await
    }

    /// Delete all dependencies for a pack
    #[oai(path = "/pack_dependencies/:pack_name", method = "delete", tag = Tag::Dependency)]
    async fn pack_dependencies_delete(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(pack_name): Path<String>,
    ) -> Result<Json<Vec<Dependency>>, poem::Error> {
        self.dependencies_delete(pool, &DependencyType::Pack, &pack_name)
            .await
    }
}
