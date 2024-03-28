use crate::db::{
    domain_drop, domain_insert, domain_select, domain_select_search, domain_update, model_drop,
    model_insert, model_select, model_select_search, model_update, Domain, DomainModels,
    DomainParam, Model, ModelParam,
};
use poem::{
    error::{BadRequest, Conflict, InternalServerError, NotFound},
    http::StatusCode,
};
use poem_openapi::Object;
use sqlx::PgPool;
use validator::Validate;

const PAGE_SIZE: u64 = 50;

/// Domain Search Results
#[derive(Object)]
pub struct DomainSearch {
    domains: Vec<Domain>,
    page: u64,
    more: bool,
}

/// Model Search Results
#[derive(Object)]
pub struct ModelSearch {
    models: Vec<Model>,
    page: u64,
    more: bool,
}

/// Add a domain
pub async fn domain_add(
    pool: &PgPool,
    domain_param: &DomainParam,
    username: &str,
) -> Result<Domain, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    domain_param.validate().map_err(BadRequest)?;

    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Add new domain
    let domain = domain_insert(&mut tx, domain_param, username)
        .await
        .map_err(Conflict)?;

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(domain)
}

/// Read details of a domain
pub async fn domain_read(pool: &PgPool, domain_name: &str) -> Result<Domain, poem::Error> {
    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Pull domain
    let domain = domain_select(&mut tx, domain_name)
        .await
        .map_err(NotFound)?;

    Ok(domain)
}

/// Read details of a domain and add model details for that domain
pub async fn domain_models_read(
    pool: &PgPool,
    domain_name: &str,
) -> Result<DomainModels, poem::Error> {
    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Pull domain_models
    let domain_models = domain_select(&mut tx, domain_name)
        .await
        .map_err(NotFound)?
        .add_models(&mut tx)
        .await?;

    Ok(domain_models)
}

/// Read details of many domains
pub async fn domain_read_search(
    pool: &PgPool,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
    page: &u64,
) -> Result<DomainSearch, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;
    let next_offset = (page + 1) * PAGE_SIZE;

    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Pull the Domains
    let domains = domain_select_search(
        &mut tx,
        domain_name,
        owner,
        extra,
        &Some(PAGE_SIZE),
        &Some(offset),
    )
    .await
    .map_err(InternalServerError)?;

    // More domains present?
    let next_domain = domain_select_search(
        &mut tx,
        domain_name,
        owner,
        extra,
        &Some(PAGE_SIZE),
        &Some(next_offset),
    )
    .await
    .map_err(InternalServerError)?;

    let more = !next_domain.is_empty();

    Ok(DomainSearch {
        domains,
        page: *page,
        more,
    })
}

/// Edit a Domain
pub async fn domain_edit(
    pool: &PgPool,
    domain_name: &str,
    domain_param: &DomainParam,
    username: &str,
) -> Result<Domain, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    domain_param.validate().map_err(BadRequest)?;

    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Update domain
    let update = domain_update(&mut tx, domain_name, domain_param, username).await;

    // What result did we get?
    let domain = match update {
        Ok(domain) => Ok(domain),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(domain)
}

/// Remove a Domain
pub async fn domain_remove(
    pool: &PgPool,
    domain_name: &str,
    //cascade: &bool,
) -> Result<Domain, poem::Error> {
    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Delete related models if cascade is on

    //TODO add cascade

    //TODO - Make sure no models exists for this domain
    //TODO Raise Conflict

    // Delete the domain
    let delete = domain_drop(&mut tx, domain_name).await;

    // What result did we get?
    let domain = match delete {
        Ok(domain) => Ok(domain),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(domain)
}

/// Add a domain
pub async fn model_add(
    pool: &PgPool,
    model_param: &ModelParam,
    username: &str,
) -> Result<Model, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    model_param.validate().map_err(BadRequest)?;

    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Add Model
    let insert = model_insert(&mut tx, model_param, username).await;

    // What result did we get?
    let model = match insert {
        Ok(model) => Ok(model),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(model)
}

//TODO pub async fn model_w_fields_add

/// Read details of a model
//TODO Change Model to ModelField
pub async fn model_read(pool: &PgPool, model_name: &str) -> Result<Model, poem::Error> {
    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Pull model
    let model: Model = model_select(&mut tx, model_name).await.map_err(NotFound)?;

    //TODO Add fields to single model read

    Ok(model)
}

/// Read details of many models
pub async fn model_read_search(
    pool: &PgPool,
    model_name: &Option<String>,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
    page: &u64,
) -> Result<ModelSearch, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;
    let next_offset = (page + 1) * PAGE_SIZE;

    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Pull the Models
    let models = model_select_search(
        &mut tx,
        model_name,
        domain_name,
        owner,
        extra,
        &Some(PAGE_SIZE),
        &Some(offset),
    )
    .await
    .map_err(InternalServerError)?;

    // More domains present?
    let next_model = model_select_search(
        &mut tx,
        model_name,
        domain_name,
        owner,
        extra,
        &Some(PAGE_SIZE),
        &Some(next_offset),
    )
    .await
    .map_err(InternalServerError)?;

    let more = !next_model.is_empty();

    Ok(ModelSearch {
        models,
        page: *page,
        more,
    })
}
/// Edit a Model
pub async fn model_edit(
    pool: &PgPool,
    model_name: &str,
    model_param: &ModelParam,
    username: &str,
) -> Result<Model, poem::Error> {
    // Make sure the payload we got is good (check with Validate package).
    model_param.validate().map_err(BadRequest)?;

    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Update domain
    let update = model_update(&mut tx, model_name, model_param, username).await;

    // What result did we get?
    let model = match update {
        Ok(model) => Ok(model),
        Err(sqlx::Error::RowNotFound) => Err(poem::Error::from_string(
            "domain or model does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(sqlx::Error::Database(err)) => Err(Conflict(err)),
        Err(err) => Err(InternalServerError(err)),
    }?;

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(model)
}

/// Remove a Model
pub async fn model_remove(pool: &PgPool, model_name: &str) -> Result<Model, poem::Error> {
    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    //TODO add cascade

    //TODO - Make sure no fields exists for this model
    //TODO Raise Conflict

    // Delete the model
    let model = model_drop(&mut tx, model_name).await.map_err(NotFound)?;

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(model)
}

//TODO Add Unit Test
