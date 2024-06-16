
use crate::{
    model::Model,
    pack::{ComputeType, Pack, RuntimeType},
    search::core::{SearchDomainParam, SearchDomain, SearchModel, SearchModelParam},
    domain::Domain,
};
use chrono::Utc;
use sqlx::{query_as, Postgres, QueryBuilder, Transaction};

use super::core::SearchPackParam;

/// Pull multiple domains that match by criteria
pub async fn search_domain_select(
    tx: &mut Transaction<'_, Postgres>,
    search_param: &SearchDomainParam,
    limit: &Option<u64>,
    offset: &Option<u64>,
) -> Result<Vec<Domain>, sqlx::Error> {
    // Query we will be modifying
    let mut query = QueryBuilder::<'_, Postgres>::new(
        "SELECT
            id,
            name,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date
        FROM
            domain",
    );

    // Should we add a WHERE statement?
    if search_param.domain_name.is_some()
        || search_param.owner.is_some()
        || search_param.extra.is_some()
    {
        query.push(" WHERE ");

        // Start building the WHERE statement with the "AND" separating the condition.
        let mut separated = query.separated(" AND ");

        // Fuzzy search
        if let Some(domain_name) = &search_param.domain_name {
            separated.push(format!("name ILIKE '%{domain_name}%'"));
        }
        if let Some(owner) = &search_param.owner {
            separated.push(format!("owner ILIKE '%{owner}%'"));
        }
        if let Some(extra) = &search_param.extra {
            separated.push(format!("extra::text ILIKE '%{extra}%'"));
        }
    }

    // Add ORDER BY
    query.push(" ORDER BY id ");

    // Add LIMIT
    if let Some(limit) = limit {
        query.push(format!(" LIMIT {limit} "));

        // Add OFFSET
        if let Some(offset) = offset {
            query.push(format!(" OFFSET {offset} "));
        }
    }

    // Run our generated SQL statement
    let domain = query
        .build_query_as::<Domain>()
        .fetch_all(&mut **tx)
        .await?;

    Ok(domain)
}

/// Pull multiple models that match the criteria
pub async fn search_model_select(
    tx: &mut Transaction<'_, Postgres>,
    search_param: &SearchModelParam,
    limit: &Option<u64>,
    offset: &Option<u64>,
) -> Result<Vec<Model>, sqlx::Error> {
    // Query we will be modifying
    let mut query = QueryBuilder::<'_, Postgres>::new(
        "SELECT
            model.id,
            model.name,
            model.domain_id,
            domain.name AS \"domain_name\",
            model.owner,
            model.extra,
            model.created_by,
            model.created_date,
            model.modified_by,
            model.modified_date
        FROM
            model
        LEFT JOIN
            domain
        ON
            model.domain_id = domain.id",
    );

    // Should we add a WHERE statement?
    if search_param.model_name.is_some()
        || search_param.domain_name.is_some()
        || search_param.owner.is_some()
        || search_param.extra.is_some()
    {
        query.push(" WHERE ");

        // Start building the WHERE statement with the "AND" separating the condition.
        let mut separated = query.separated(" AND ");

        // Fuzzy search
        if let Some(model_name) = &search_param.model_name {
            separated.push(format!("model.name ILIKE '%{model_name}%'"));
        }
        if let Some(domain_name) = &search_param.domain_name {
            separated.push(format!("domain.name ILIKE '%{domain_name}%'"));
        }
        if let Some(owner) = &search_param.owner {
            separated.push(format!("model.owner ILIKE '%{owner}%'"));
        }
        if let Some(extra) = &search_param.extra {
            separated.push(format!("model.extra::text ILIKE '%{extra}%'"));
        }
    }

    // Add ORDER BY
    query.push(" ORDER BY model.id ");

    // Add LIMIT
    if let Some(limit) = limit {
        query.push(format!(" LIMIT {limit} "));

        // Add OFFSET
        if let Some(offset) = offset {
            query.push(format!(" OFFSET {offset} "));
        }
    }

    // Run our generated SQL statement
    let model = query.build_query_as::<Model>().fetch_all(&mut **tx).await?;

    Ok(model)
}

/// Pull multiple packs that match the criteria
pub async fn search_pack_select(
    tx: &mut Transaction<'_, Postgres>,
    search_param: &SearchPackParam,
    limit: &Option<u64>,
    offset: &Option<u64>,
) -> Result<Vec<Pack>, sqlx::Error> {
    // Query we will be modifying
    let mut query = QueryBuilder::<'_, Postgres>::new(
        "SELECT
            pack.id,
            pack.name,
            pack.domain_id,
            domain.name AS \"domain_name\",
            pack.runtime,
            pack.compute,
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
            pack.domain_id = domain.id",
    );

    // Should we add a WHERE statement?
    if search_param.pack_name.is_some()
        || search_param.domain_name.is_some()
        || search_param.runtime.is_some()
        || search_param.compute.is_some()
        || search_param.repo.is_some()
        || search_param.owner.is_some()
        || search_param.extra.is_some()
    {
        query.push(" WHERE ");

        // Start building the WHERE statement with the "AND" separating the condition.
        let mut separated = query.separated(" AND ");

        // Fuzzy search
        if let Some(pack_name) = &search_param.pack_name {
            separated.push(format!("pack.name ILIKE '%{pack_name}%'"));
        }
        if let Some(domain_name) = &search_param.domain_name {
            separated.push(format!("domain.name ILIKE '%{domain_name}%'"));
        }
        if let Some(runtime) = search_param.runtime {
            separated.push(format!("pack.runtime = '{runtime}'"));
        }
        if let Some(compute) = search_param.compute {
            separated.push(format!("pack.compute = '{compute}'"));
        }
        if let Some(repo) = &search_param.repo {
            separated.push(format!("pack.repo ILIKE '%{repo}%'"));
        }
        if let Some(owner) = &search_param.owner {
            separated.push(format!("pack.owner ILIKE '%{owner}%'"));
        }
        if let Some(extra) = &search_param.extra {
            separated.push(format!("pack.extra::text ILIKE '%{extra}%'"));
        }
    }

    // Add ORDER BY
    query.push(" ORDER BY pack.id ");

    // Add LIMIT
    if let Some(limit) = limit {
        query.push(format!(" LIMIT {limit} "));

        // Add OFFSET
        if let Some(offset) = offset {
            query.push(format!(" OFFSET {offset} "));
        }
    }

    // Run our generated SQL statement
    let pack = query.build_query_as::<Pack>().fetch_all(&mut **tx).await?;

    Ok(pack)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        util::test_utils::{
            gen_test_domain_json, gen_test_field_json, post_test_domain, post_test_field, gen_test_model_json, post_test_model,
        },
    };
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use sqlx::PgPool;

    /// Test domain search
    #[sqlx::test]
    async fn test_search_domain(pool: PgPool) {

        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: None,
                owner: None,
                extra: None,
            };

            let domains = search_domain_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 2);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: Some("abcdef".to_string()),
                owner: None,
                extra: None,
            };

            let domains = search_domain_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 0);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: Some("test".to_string()),
                owner: None,
                extra: None,
            };

            let domains = search_domain_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: Some("test".to_string()),
                owner: Some("test.com".to_string()),
                extra: None,
            };

            let domains = search_domain_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: Some("test".to_string()),
                owner: Some("test.com".to_string()),
                extra: Some("abc".to_string()),
            };

            let domains = search_domain_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: None,
                owner: None,
                extra: None,
            };

            let domains = search_domain_select(&mut tx, &search_param, &Some(1), &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchDomainParam {
                domain_name: None,
                owner: None,
                extra: None,
            };

            let domains = search_domain_select(&mut tx, &search_param, &Some(1), &Some(1))
                .await
                .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "foobar_domain");
        }
    }
    


    /// Test model search
    #[sqlx::test]
    async fn test_search_model(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;


        // Model to create
        let body = gen_test_model_json("test_model", "test_domain");
        post_test_model(&body, &pool).await;

        let body = gen_test_model_json("test_model_2", "test_domain");
        post_test_model(&body, &pool).await;
        
        let body = gen_test_model_json("foobar_model", "foobar_domain");
        post_test_model(&body, &pool).await;

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: None,
                owner: None,
                extra: None,
            };

            let models = search_model_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(models.len(), 3);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model_2");
            assert_eq!(models[2].name, "foobar_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("abcdef".to_string()),
                domain_name: None,
                owner: None,
                extra: None,
            };

            let models = search_model_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(models.len(), 0);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("model".to_string()),
                domain_name: None,
                owner: None,
                extra: None,
            };

            let models = search_model_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(models.len(), 3);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model_2");
            assert_eq!(models[2].name, "foobar_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: Some("model_2".to_string()),
                domain_name: None,
                owner: None,
                extra: None,
            };

            let models = search_model_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(models.len(), 1);
            assert_eq!(models[0].name, "test_model_2");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: Some("test".to_string()),
                owner: None,
                extra: None,
            };

            let models = search_model_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(models.len(), 2);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model_2");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: None,
                owner: Some("test_model%@test.com".to_string()),
                extra: None,
            };

            let models = search_model_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(models.len(), 2);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model_2");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: None,
                owner: None,
                extra: Some("abc".to_string()),
            };

            let models = search_model_select(&mut tx, &search_param, &None, &None)
                .await
                .unwrap();

            assert_eq!(models.len(), 3);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model_2");
            assert_eq!(models[2].name, "foobar_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: None,
                owner: None,
                extra: None,
            };

            let models = search_model_select(&mut tx, &search_param, &Some(1), &None)
                .await
                .unwrap();

            assert_eq!(models.len(), 1);
            assert_eq!(models[0].name, "test_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let search_param = SearchModelParam {
                model_name: None,
                domain_name: None,
                owner: None,
                extra: None,
            };

            let models = search_model_select(&mut tx, &search_param, &Some(1), &Some(1))
                .await
                .unwrap();

            assert_eq!(models.len(), 1);
            assert_eq!(models[0].name, "test_model_2");
        }
    }


    /// Test pack search
    #[test]
    #[should_panic]
    fn test_search_pack() {
        todo!();
    }
}
