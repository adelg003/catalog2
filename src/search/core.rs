use crate::{
    domain::Domain,
    model::Model,
    pack::{ComputeType, Pack, RuntimeType},
    search::db::{search_domain_select, search_model_select, search_pack_select},
    util::PAGE_SIZE,
};
use poem::error::InternalServerError;
use poem_openapi::Object;
use sqlx::{Postgres, Transaction};

/// Domain Search Results
#[derive(Object)]
pub struct SearchDomain {
    domains: Vec<Domain>,
    page: u64,
    more: bool,
}

/// Params for searching for domains
pub struct SearchDomainParam {
    pub domain_name: Option<String>,
    pub owner: Option<String>,
    pub extra: Option<String>,
}

/// Model Search Results
#[derive(Object)]
pub struct SearchModel {
    models: Vec<Model>,
    page: u64,
    more: bool,
}

/// Params for searching for models
pub struct SearchModelParam {
    pub model_name: Option<String>,
    pub domain_name: Option<String>,
    pub owner: Option<String>,
    pub extra: Option<String>,
}

/// Pack Search Results
#[derive(Object)]
pub struct SearchPack {
    packs: Vec<Pack>,
    page: u64,
    more: bool,
}

/// Params for searching for packs
pub struct SearchPackParam {
    pub pack_name: Option<String>,
    pub domain_name: Option<String>,
    pub runtime: Option<RuntimeType>,
    pub compute: Option<ComputeType>,
    pub repo: Option<String>,
    pub owner: Option<String>,
    pub extra: Option<String>,
}

/// Read details of many domains
pub async fn search_domain_read(
    tx: &mut Transaction<'_, Postgres>,
    search_param: &SearchDomainParam,
    page: &u64,
) -> Result<SearchDomain, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;
    let next_offset = (page + 1) * PAGE_SIZE;

    // Pull the Domains
    let domains = search_domain_select(tx, search_param, &Some(PAGE_SIZE), &Some(offset))
        .await
        .map_err(InternalServerError)?;

    // More domains present?
    let next_domain = search_domain_select(tx, search_param, &Some(PAGE_SIZE), &Some(next_offset))
        .await
        .map_err(InternalServerError)?;

    let more = !next_domain.is_empty();

    Ok(SearchDomain {
        domains,
        page: *page,
        more,
    })
}

/// Read details of many models
pub async fn search_model_read(
    tx: &mut Transaction<'_, Postgres>,
    search_param: &SearchModelParam,
    page: &u64,
) -> Result<SearchModel, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;
    let next_offset = (page + 1) * PAGE_SIZE;

    // Pull the Models
    let models = search_model_select(tx, search_param, &Some(PAGE_SIZE), &Some(offset))
        .await
        .map_err(InternalServerError)?;

    // More models present?
    let next_model = search_model_select(tx, search_param, &Some(PAGE_SIZE), &Some(next_offset))
        .await
        .map_err(InternalServerError)?;

    let more = !next_model.is_empty();

    Ok(SearchModel {
        models,
        page: *page,
        more,
    })
}

/// Read details of many packs
pub async fn search_pack_read(
    tx: &mut Transaction<'_, Postgres>,
    search_param: &SearchPackParam,
    page: &u64,
) -> Result<SearchPack, poem::Error> {
    // Compute offset
    let offset = page * PAGE_SIZE;
    let next_offset = (page + 1) * PAGE_SIZE;

    // Pull the Pack
    let packs = search_pack_select(tx, search_param, &Some(PAGE_SIZE), &Some(offset))
        .await
        .map_err(InternalServerError)?;

    // More packs present?
    let next_pack = search_pack_select(tx, search_param, &Some(PAGE_SIZE), &Some(next_offset))
        .await
        .map_err(InternalServerError)?;

    let more = !next_pack.is_empty();

    Ok(SearchPack {
        packs,
        page: *page,
        more,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_utils::{
        gen_test_domain_json, gen_test_model_json, post_test_domain, post_test_model,
    };
    use pretty_assertions::assert_eq;
    use sqlx::PgPool;

    /// Test domain search
    #[sqlx::test]
    async fn test_search_domain_read(pool: PgPool) {
        {
            for index in 0..50 {
                let body = gen_test_domain_json(&format!("test_domain_{index}"));
                post_test_domain(&body, &pool).await;
            }

            let body = gen_test_domain_json(&format!("foobar_domain"));
            post_test_domain(&body, &pool).await;
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: None,
                owner: None,
                extra: None,
            };

            let search = search_domain_read(&mut tx, &search_param, &0)
                .await
                .unwrap();

            assert_eq!(search.domains.len(), 50);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, true);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: None,
                owner: None,
                extra: None,
            };

            let search = search_domain_read(&mut tx, &search_param, &1)
                .await
                .unwrap();

            assert_eq!(search.domains.len(), 1);
            assert_eq!(search.page, 1);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: Some("abcdef".to_string()),
                owner: None,
                extra: None,
            };

            let search = search_domain_read(&mut tx, &search_param, &0)
                .await
                .unwrap();

            assert_eq!(search.domains.len(), 0);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: Some("foobar".to_string()),
                owner: None,
                extra: None,
            };

            let search = search_domain_read(&mut tx, &search_param, &0)
                .await
                .unwrap();

            assert_eq!(search.domains.len(), 1);
            assert_eq!(search.domains[0].name, "foobar_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: Some("foobar".to_string()),
                owner: Some("test.com".to_string()),
                extra: None,
            };

            let search = search_domain_read(&mut tx, &search_param, &0)
                .await
                .unwrap();

            assert_eq!(search.domains.len(), 1);
            assert_eq!(search.domains[0].name, "foobar_domain");
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: Some("foobar".to_string()),
                owner: Some("test.com".to_string()),
                extra: Some("abc".to_string()),
            };

            let search = search_domain_read(&mut tx, &search_param, &0)
                .await
                .unwrap();

            assert_eq!(search.domains.len(), 1);
            assert_eq!(search.domains[0].name, "foobar_domain");
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }
    }

    /// Test model search
    #[sqlx::test]
    async fn test_search_model_read(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        {
            for index in 0..50 {
                // Model to create
                let body = gen_test_model_json(&format!("test_model_{index}"), "test_domain");
                post_test_model(&body, &pool).await;
            }

            // Model to create
            let body = gen_test_model_json(&format!("foobar_model"), "foobar_domain");
            post_test_model(&body, &pool).await;
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: None,
                owner: None,
                extra: None,
            };

            let search = search_model_read(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 50);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, true);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: None,
                owner: None,
                extra: None,
            };

            let search = search_model_read(&mut tx, &search_param, &1).await.unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.page, 1);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("test".to_string()),
                domain_name: None,
                owner: None,
                extra: None,
            };

            let search = search_model_read(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 50);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("abcdef".to_string()),
                domain_name: None,
                owner: None,
                extra: None,
            };

            let search = search_model_read(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 0);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("foobar".to_string()),
                domain_name: None,
                owner: None,
                extra: None,
            };

            let search = search_model_read(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.models[0].name, "foobar_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: Some("test".to_string()),
                owner: None,
                extra: None,
            };

            let search = search_model_read(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 50);
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("foobar".to_string()),
                domain_name: None,
                owner: Some("test.com".to_string()),
                extra: None,
            };

            let search = search_model_read(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.models[0].name, "foobar_model");
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("foobar".to_string()),
                domain_name: None,
                owner: Some("test.com".to_string()),
                extra: Some("abc".to_string()),
            };

            let search = search_model_read(&mut tx, &search_param, &0).await.unwrap();

            assert_eq!(search.models.len(), 1);
            assert_eq!(search.models[0].name, "foobar_model");
            assert_eq!(search.page, 0);
            assert_eq!(search.more, false);
        }
    }

    /// Test pack search
    #[test]
    #[should_panic]
    fn test_pack_read_search() {
        todo!();
    }
}
