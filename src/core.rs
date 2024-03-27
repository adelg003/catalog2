use crate::db::{
    domain_drop, domain_insert, domain_select, domain_select_search, domain_update, model_drop,
    model_insert, model_select, model_select_search, model_update, Domain, Model,
};
use poem::{
    error::{BadRequest, Conflict, InternalServerError, NotFound},
    http::StatusCode,
};
use poem_openapi::Object;
use regex::Regex;
use sqlx::PgPool;
use validator::{Validate, ValidationError};

const PAGE_SIZE: u64 = 50;

/// Domain with models
#[derive(Object)]
pub struct DomainModel {
    pub domain: Domain,
    pub models: Vec<Model>,
}

/// How to create a new domain
#[derive(Object, Validate)]
pub struct DomainParam {
    pub domain: String,
    #[validate(email)]
    pub owner: String,
    pub extra: serde_json::Value,
}

/// Domain Search Results
#[derive(Object)]
pub struct DomainSearch {
    domains: Vec<Domain>,
    page: u64,
    more: bool,
}

//TODO ModelFields

/// How to create a new model
#[derive(Object, Validate)]
pub struct ModelParam {
    #[validate(custom(function = dbx_validater))]
    pub model: String,
    domain: String,
    #[validate(email)]
    pub owner: String,
    pub extra: serde_json::Value,
}

/// Model Search Results
#[derive(Object)]
pub struct ModelSearch {
    models: Vec<Model>,
    page: u64,
    more: bool,
}

/// Only allow for valid DBX name, meaning letters, number, dashes, and underscores. First
/// character needs to be a letter. Also, since DBX is case-insensitive, only allow lower
/// characters to ensure unique constraints work.
fn dbx_validater(obj_name: &str) -> Result<(), ValidationError> {
    let dbx_regex = Regex::new("^[a-z][a-z0-9_-]*$");
    match dbx_regex {
        Ok(re) if re.is_match(obj_name) => Ok(()),
        _ => Err(ValidationError::new("Failed DBX Regex Check")),
    }
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

    // Check if domain already exists
    match domain_select(&mut tx, &domain_param.domain).await {
        Ok(_) => Err(poem::Error::from_string(
            "Domain already exists",
            StatusCode::CONFLICT,
        )),
        Err(sqlx::Error::RowNotFound) => Ok(()),
        Err(err) => Err(InternalServerError(err)),
    }?;

    // Add new domain
    domain_insert(&mut tx, domain_param, username)
        .await
        .map_err(InternalServerError)?;

    // Pull domain
    let domain = domain_select(&mut tx, &domain_param.domain)
        .await
        .map_err(InternalServerError)?;

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(domain)
}

/// Read details of a domain
pub async fn domain_read(pool: &PgPool, domain_name: &str) -> Result<DomainModel, poem::Error> {
    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Pull domain
    let domain = domain_select(&mut tx, domain_name)
        .await
        .map_err(NotFound)?;

    // Add Models
    let domain_models = domain.add_models(&mut tx).await?;

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

    // Check to make sure domain already exists
    domain_select(&mut tx, domain_name)
        .await
        .map_err(NotFound)?;

    // Update domain
    domain_update(&mut tx, domain_name, domain_param, username)
        .await
        .map_err(Conflict)?;

    // Pull domain
    let domain = domain_select(&mut tx, &domain_param.domain)
        .await
        .map_err(InternalServerError)?;

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(domain)
}

/// Remove a Domain
pub async fn domain_remove(pool: &PgPool, domain_name: &str) -> Result<Domain, poem::Error> {
    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Check to make sure domain already exists
    let domain = domain_select(&mut tx, domain_name)
        .await
        .map_err(NotFound)?;

    //TODO add cascade

    //TODO - Make sure no models exists for this domain
    //TODO Raise Conflict

    // Delete the domain
    domain_drop(&mut tx, domain_name)
        .await
        .map_err(InternalServerError)?;

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

    // Check if model already exists
    match model_select(&mut tx, &model_param.model).await {
        Ok(_) => Err(poem::Error::from_string(
            "Model already exists",
            StatusCode::CONFLICT,
        )),
        Err(sqlx::Error::RowNotFound) => Ok(()),
        Err(err) => Err(InternalServerError(err)),
    }?;

    // Pull the parent domain
    let domain = domain_select(&mut tx, &model_param.domain)
        .await
        .map_err(NotFound)?;

    // Add new model
    model_insert(&mut tx, model_param, &domain.id, username)
        .await
        .map_err(InternalServerError)?;

    // Pull model
    let model: Model = model_select(&mut tx, &model_param.model)
        .await
        .map_err(InternalServerError)?;

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

    // Check to make sure model already exists
    model_select(&mut tx, model_name).await.map_err(NotFound)?;

    // Pull the related Domain details
    let domain = domain_select(&mut tx, &model_param.domain)
        .await
        .map_err(NotFound)?;

    // Update model
    model_update(&mut tx, model_name, model_param, &domain.id, username)
        .await
        .map_err(Conflict)?;

    // Pull the new Model
    let model: Model = model_select(&mut tx, &model_param.model)
        .await
        .map_err(InternalServerError)?;

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(model)
}

/// Remove a Model
pub async fn model_remove(pool: &PgPool, model_name: &str) -> Result<Model, poem::Error> {
    // Start Transaction
    let mut tx = pool.begin().await.map_err(InternalServerError)?;

    // Check to make sure model already exists
    let model: Model = model_select(&mut tx, model_name).await.map_err(NotFound)?;

    //TODO add cascade

    //TODO - Make sure no fields exists for this model
    //TODO Raise Conflict

    // Delete the model
    model_drop(&mut tx, model_name)
        .await
        .map_err(InternalServerError)?;

    // Commit Transaction
    tx.commit().await.map_err(InternalServerError)?;

    Ok(model)
}

//TODO Add Unit Test
