use crate::{
    api::Tag,
    auth::{Auth, TokenAuth},
    pack::core::{
        pack_add, pack_edit, pack_read, pack_read_with_children, pack_remove, Pack, PackChildren,
        PackParam,
    },
};
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{param::Path, payload::Json, OpenApi};
use sqlx::PgPool;

/// Struct we will build our REST API / Webserver
pub struct PackApi;

#[OpenApi]
impl PackApi {
    /// Add a pack to the pack table
    #[oai(path = "/pack", method = "post", tag = Tag::Pack)]
    async fn pack_post(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Json(pack_param): Json<PackParam>,
    ) -> Result<Json<Pack>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Add a pack
        let pack = pack_add(&mut tx, &pack_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(pack))
    }

    /// Get a single pack
    #[oai(path = "/pack/:pack_name", method = "get", tag = Tag::Pack)]
    async fn pack_get(
        &self,
        Data(pool): Data<&PgPool>,
        Path(pack_name): Path<String>,
    ) -> Result<Json<Pack>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull pack
        let pack = pack_read(&mut tx, &pack_name).await?;

        Ok(Json(pack))
    }

    /// Change a pack to the pack table
    #[oai(path = "/pack/:pack_name", method = "put", tag = Tag::Pack)]
    async fn pack_put(
        &self,
        auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(pack_name): Path<String>,
        Json(pack_param): Json<PackParam>,
    ) -> Result<Json<Pack>, poem::Error> {
        // Get user from authentication.
        let username = auth.username();

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Run Pack edit logic
        let pack = pack_edit(&mut tx, &pack_name, &pack_param, username).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(pack))
    }

    /// Delete a pack
    #[oai(path = "/pack/:pack_name", method = "delete", tag = Tag::Pack)]
    async fn pack_delete(
        &self,
        _auth: TokenAuth,
        Data(pool): Data<&PgPool>,
        Path(pack_name): Path<String>,
    ) -> Result<Json<Pack>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Delete Pack
        let pack = pack_remove(&mut tx, &pack_name).await?;

        // Commit Transaction
        tx.commit().await.map_err(InternalServerError)?;

        Ok(Json(pack))
    }

    /// Get a single model and its fields, and it dependencies
    #[oai(path = "/pack_with_children/:pack_name", method = "get", tag = Tag::PackWithChildren)]
    async fn pack_get_with_children(
        &self,
        Data(pool): Data<&PgPool>,
        Path(pack_name): Path<String>,
    ) -> Result<Json<PackChildren>, poem::Error> {
        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull Pack with dependencies
        let pack_children = pack_read_with_children(&mut tx, &pack_name).await?;

        Ok(Json(pack_children))
    }
}

#[cfg(test)]
mod tests {

    /// Test create pack
    #[test]
    #[should_panic]
    fn test_pack_post() {
        todo!();
    }

    /// Test pack post where no domain found
    #[test]
    #[should_panic]
    fn test_pack_post_not_found() {
        todo!();
    }

    /// Test double pack create conflict
    #[test]
    #[should_panic]
    fn test_pack_post_conflict() {
        todo!();
    }

    /// Test pack get
    #[test]
    #[should_panic]
    fn test_pack_get() {
        todo!();
    }

    /// Test Reading a pack that does not exists
    #[test]
    #[should_panic]
    fn test_pack_get_not_found() {
        todo!();
    }

    /// Test pack update
    #[test]
    #[should_panic]
    fn test_pack_put() {
        todo!();
    }

    /// Test pack update when not found
    #[test]
    #[should_panic]
    fn test_pack_put_not_found() {
        todo!();
    }

    /// Test pack update with Conflict
    #[test]
    #[should_panic]
    fn test_pack_put_conflict() {
        todo!();
    }

    /// Test pack delete
    #[test]
    #[should_panic]
    fn test_pack_delete() {
        todo!();
    }

    /// Test pack delete if not exists
    #[test]
    #[should_panic]
    fn test_pack_delete_not_exists() {
        todo!();
    }

    /// Test model delete if still have children
    #[test]
    #[should_panic]
    fn test_pack_delete_conflict() {
        todo!();
    }
}
