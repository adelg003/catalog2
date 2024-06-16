use crate::{
    api::Tag,
    pack::{ComputeType, RuntimeType},
    search::core::{
        search_domain_read, search_model_read, search_pack_read, SearchDomain, SearchModelParam,
        SearchPack, SearchPackParam,
    },
};
use poem::{error::InternalServerError, web::Data};
use poem_openapi::{param::Query, payload::Json, OpenApi};
use sqlx::PgPool;

use super::core::{SearchDomainParam, SearchModel};

/// Struct we will build our REST API / Webserver
pub struct SearchApi;

#[OpenApi]
impl SearchApi {
    /// Search domains
    #[oai(path = "/search/domain", method = "get", tag = Tag::Search)]
    async fn search_domain_get(
        &self,
        Data(pool): Data<&PgPool>,
        Query(domain_name): Query<Option<String>>,
        Query(owner): Query<Option<String>>,
        Query(extra): Query<Option<String>>,
        Query(page): Query<Option<u64>>,
    ) -> Result<Json<SearchDomain>, poem::Error> {
        // Default no page to 0
        let page = page.unwrap_or(0);

        // Search Params
        let search_param = SearchDomainParam {
            domain_name,
            owner,
            extra,
        };

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull domain
        let search_domain = search_domain_read(&mut tx, &search_param, &page).await?;

        Ok(Json(search_domain))
    }

    /// Search models
    #[oai(path = "/search/model", method = "get", tag = Tag::Search)]
    async fn search_model_get(
        &self,
        Data(pool): Data<&PgPool>,
        Query(model_name): Query<Option<String>>,
        Query(domain_name): Query<Option<String>>,
        Query(owner): Query<Option<String>>,
        Query(extra): Query<Option<String>>,
        Query(page): Query<Option<u64>>,
    ) -> Result<Json<SearchModel>, poem::Error> {
        // Default no page to 0
        let page = page.unwrap_or(0);

        // Search Params
        let search_param = SearchModelParam {
            model_name,
            domain_name,
            owner,
            extra,
        };

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull models
        let search_model = search_model_read(&mut tx, &search_param, &page).await?;

        Ok(Json(search_model))
    }

    /// Search pack
    #[oai(path = "/search/pack", method = "get", tag = Tag::Search)]
    #[allow(clippy::too_many_arguments)]
    async fn search_pack_get(
        &self,
        Data(pool): Data<&PgPool>,
        Query(pack_name): Query<Option<String>>,
        Query(domain_name): Query<Option<String>>,
        Query(runtime): Query<Option<RuntimeType>>,
        Query(compute): Query<Option<ComputeType>>,
        Query(repo): Query<Option<String>>,
        Query(owner): Query<Option<String>>,
        Query(extra): Query<Option<String>>,
        Query(page): Query<Option<u64>>,
    ) -> Result<Json<SearchPack>, poem::Error> {
        // Default no page to 0
        let page = page.unwrap_or(0);

        // Search Params
        let search_param = SearchPackParam {
            pack_name,
            domain_name,
            runtime,
            compute,
            repo,
            owner,
            extra,
        };

        // Start Transaction
        let mut tx = pool.begin().await.map_err(InternalServerError)?;

        // Pull packs
        let search_pack = search_pack_read(&mut tx, &search_param, &page).await?;

        Ok(Json(search_pack))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_utils::{
        gen_test_domain_json, gen_test_model_json, post_test_domain, post_test_model,
    };
    use poem::test::TestClient;
    use poem_openapi::OpenApiService;

    /// Test domain search
    #[sqlx::test]
    async fn test_search_domain_get(pool: PgPool) {
        for index in 0..50 {
            // Domain to create
            let body = gen_test_domain_json(&format!("test_domain_{index}"));
            post_test_domain(&body, &pool).await;
        }

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        // Test Client
        let ep = OpenApiService::new(SearchApi, "test", "1.0");
        let cli = TestClient::new(ep);

        {
            // Test Request
            let response = cli
                .get("/search/domain")
                .header("Content-Type", "application/json; charset=utf-8")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("domains").array().assert_len(50);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(true);
        }

        {
            // Test Request
            let response = cli
                .get("/search/domain")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("page", &1)
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("domains").array().assert_len(1);
            json_value.object().get("page").assert_i64(1);
            json_value.object().get("more").assert_bool(false);
        }

        {
            // Test Request
            let response = cli
                .get("/search/domain")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("domain_name", &"abcdef")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("domains").array().assert_len(0);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);
        }

        {
            // Test Request
            let response = cli
                .get("/search/domain")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("domain_name", &"foobar")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("domains").array().assert_len(1);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);

            json_value.object().get("domains").object_array()[0]
                .get("name")
                .assert_string("foobar_domain");
        }

        {
            // Test Request
            let response = cli
                .get("/search/domain")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("domain_name", &"foobar")
                .query("owner", &"test.com")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("domains").array().assert_len(1);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);

            json_value.object().get("domains").object_array()[0]
                .get("name")
                .assert_string("foobar_domain");
        }

        {
            // Test Request
            let response = cli
                .get("/search/domain")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("domain_name", &"foobar")
                .query("owner", &"test.com")
                .query("extra", &"abc")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("domains").array().assert_len(1);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);

            json_value.object().get("domains").object_array()[0]
                .get("name")
                .assert_string("foobar_domain");
        }
    }

    /// Test model search
    #[sqlx::test]
    async fn test_search_model_get(pool: PgPool) {
        // Domain to create
        let body = gen_test_domain_json("test_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        for index in 0..50 {
            let body = gen_test_model_json(&format!("test_model_{index}"), "test_domain");
            post_test_model(&body, &pool).await;
        }

        // Domain to create
        let body = gen_test_domain_json("foobar_domain");
        post_test_domain(&body, &pool).await;

        // Model to create
        let body = gen_test_model_json("foobar_model", "foobar_domain");
        post_test_model(&body, &pool).await;

        // Test Client
        let ep = OpenApiService::new(SearchApi, "test", "1.0");
        let cli = TestClient::new(ep);

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(50);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(true);
        }

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("page", &1)
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(1);
            json_value.object().get("page").assert_i64(1);
            json_value.object().get("more").assert_bool(false);
        }

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("model_name", &"test")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(50);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);
        }

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("model_name", &"abcdef")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(0);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);
        }

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("model_name", &"foobar")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(1);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);
        }

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("domain_name", &"test")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(50);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);
        }

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("model_name", &"foobar")
                .query("owner", &"test.com")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(1);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);

            json_value.object().get("models").object_array()[0]
                .get("name")
                .assert_string("foobar_model");
        }

        {
            // Test Request
            let response = cli
                .get("/search/model")
                .header("Content-Type", "application/json; charset=utf-8")
                .query("model_name", &"foobar")
                .query("owner", &"test.com")
                .query("extra", &"abc")
                .data(pool.clone())
                .send()
                .await;

            // Check status
            response.assert_status_is_ok();

            // Check Values
            let test_json = response.json().await;
            let json_value = test_json.value();

            json_value.object().get("models").array().assert_len(1);
            json_value.object().get("page").assert_i64(0);
            json_value.object().get("more").assert_bool(false);

            json_value.object().get("models").object_array()[0]
                .get("name")
                .assert_string("foobar_model");
        }
    }

    /// Test pack search
    #[test]
    #[should_panic]
    fn test_search_pack_get() {
        todo!();
    }
}
