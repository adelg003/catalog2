use crate::core::{
    DbxDataType, Domain, DomainParam, Field, FieldParam, FieldParamUpdate, Model, ModelParam,
};
use chrono::Utc;
use sqlx::{query, query_as, Postgres, QueryBuilder, Transaction};

/// Add a domain to the domain table
pub async fn domain_insert(
    tx: &mut Transaction<'_, Postgres>,
    domain_param: &DomainParam,
    username: &str,
) -> Result<Domain, sqlx::Error> {
    let domain = query_as!(
        Domain,
        "INSERT INTO domain (
            name,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date
        ) VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7
        ) RETURNING
            id,
            name,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date",
        domain_param.name,
        domain_param.owner,
        domain_param.extra,
        username,
        Utc::now(),
        username,
        Utc::now(),
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(domain)
}

/// Pull one domain
pub async fn domain_select(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<Domain, sqlx::Error> {
    let domain = query_as!(
        Domain,
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
            domain
        WHERE
            name = $1",
        domain_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(domain)
}

/// Pull multiple domains that match the criteria
pub async fn domain_select_search(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
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
    if domain_name.is_some() || owner.is_some() || extra.is_some() {
        query.push(" WHERE ");

        // Start building the WHERE statement with the "AND" separating the condition.
        let mut separated = query.separated(" AND ");

        // Fuzzy search
        if let Some(domain_name) = domain_name {
            separated.push(format!("name ILIKE '%{}%'", domain_name));
        }
        if let Some(owner) = owner {
            separated.push(format!("owner ILIKE '%{}%'", owner));
        }
        if let Some(extra) = extra {
            separated.push(format!("extra::text ILIKE '%{}%'", extra));
        }
    }

    // Add ORDER BY
    query.push(" ORDER BY id ");

    // Add LIMIT
    if let Some(limit) = limit {
        query.push(format!(" LIMIT {} ", limit));

        // Add OFFSET
        if let Some(offset) = offset {
            query.push(format!(" OFFSET {} ", offset));
        }
    }

    // Run our generated SQL statement
    let domain = query
        .build_query_as::<Domain>()
        .fetch_all(&mut **tx)
        .await?;

    Ok(domain)
}

/// Update a domain
pub async fn domain_update(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
    domain_param: &DomainParam,
    username: &str,
) -> Result<Domain, sqlx::Error> {
    let domain = query_as!(
        Domain,
        "UPDATE
            domain
        SET 
            name = $1,
            owner = $2,
            extra = $3,
            modified_by = $4,
            modified_date = $5
        WHERE
            name = $6
        RETURNING
            id,
            name,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date",
        domain_param.name,
        domain_param.owner,
        domain_param.extra,
        username,
        Utc::now(),
        domain_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(domain)
}

/// Delete a domain
pub async fn domain_drop(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<Domain, sqlx::Error> {
    let domain = query_as!(
        Domain,
        "DELETE FROM
            domain
        WHERE
            name = $1
        RETURNING
            id,
            name,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date",
        domain_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(domain)
}

/// Add a model to the model table
pub async fn model_insert(
    tx: &mut Transaction<'_, Postgres>,
    model_param: &ModelParam,
    username: &str,
) -> Result<Model, sqlx::Error> {
    let domain = domain_select(tx, &model_param.domain_name).await?;

    query!(
        "INSERT INTO model (
            name,
            domain_id,
            owner,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date
        ) VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8
        )",
        model_param.name,
        domain.id,
        model_param.owner,
        model_param.extra,
        username,
        Utc::now(),
        username,
        Utc::now(),
    )
    .execute(&mut **tx)
    .await?;

    // Pull the row
    let model = model_select(tx, &model_param.name).await?;

    Ok(model)
}

/// Pull one model
pub async fn model_select(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Model, sqlx::Error> {
    let model = query_as!(
        Model,
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
        on
            model.domain_id = domain.id 
        WHERE
            model.name = $1",
        model_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(model)
}

/// Pull many models by domain
pub async fn model_select_by_domain(
    tx: &mut Transaction<'_, Postgres>,
    domain_name: &str,
) -> Result<Vec<Model>, sqlx::Error> {
    let model = query_as!(
        Model,
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
        on
            model.domain_id = domain.id 
        WHERE
            domain.name = $1",
        domain_name,
    )
    .fetch_all(&mut **tx)
    .await?;

    Ok(model)
}

/// Pull multiple models that match the criteria
pub async fn model_select_search(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &Option<String>,
    domain_name: &Option<String>,
    owner: &Option<String>,
    extra: &Option<String>,
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
        on
            model.domain_id = domain.id",
    );

    // Should we add a WHERE statement?
    if model_name.is_some() || domain_name.is_some() || owner.is_some() || extra.is_some() {
        query.push(" WHERE ");

        // Start building the WHERE statement with the "AND" separating the condition.
        let mut separated = query.separated(" AND ");

        // Fuzzy search
        if let Some(model_name) = model_name {
            separated.push(format!("model.name ILIKE '%{}%'", model_name));
        }
        if let Some(domain_name) = domain_name {
            separated.push(format!("domain.name ILIKE '%{}%'", domain_name));
        }
        if let Some(owner) = owner {
            separated.push(format!("model.owner ILIKE '%{}%'", owner));
        }
        if let Some(extra) = extra {
            separated.push(format!("model.extra::text ILIKE '%{}%'", extra));
        }
    }

    // Add ORDER BY
    query.push(" ORDER BY model.id ");

    // Add LIMIT
    if let Some(limit) = limit {
        query.push(format!(" LIMIT {} ", limit));

        // Add OFFSET
        if let Some(offset) = offset {
            query.push(format!(" OFFSET {} ", offset));
        }
    }

    // Run our generated SQL statement
    let model = query.build_query_as::<Model>().fetch_all(&mut **tx).await?;

    Ok(model)
}

/// Update a model
pub async fn model_update(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    model_param: &ModelParam,
    username: &str,
) -> Result<Model, sqlx::Error> {
    // Make sure related domain exists
    let domain = domain_select(tx, &model_param.domain_name).await?;

    let rows_affected = query!(
        "UPDATE
            model
        SET 
            name = $1,
            domain_id = $2,
            owner = $3,
            extra = $4,
            modified_by = $5,
            modified_date = $6
        WHERE
            name = $7",
        model_param.name,
        domain.id,
        model_param.owner,
        model_param.extra,
        username,
        Utc::now(),
        model_name,
    )
    .execute(&mut **tx)
    .await?
    .rows_affected();

    // Check if any rows were updated.
    if rows_affected == 0 {
        return Err(sqlx::Error::RowNotFound);
    }

    // Pull the row, but with the domain name added
    let model = model_select(tx, &model_param.name).await?;

    Ok(model)
}

/// Delete a model
pub async fn model_drop(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Model, sqlx::Error> {
    // Pull the row
    let model = model_select(tx, model_name).await?;

    // Now run the delete since we have the row in memory
    query!(
        "DELETE FROM
            model
        WHERE
            name = $1",
        model_name,
    )
    .execute(&mut **tx)
    .await?;

    Ok(model)
}

/// Add a field to the field table
pub async fn field_insert(
    tx: &mut Transaction<'_, Postgres>,
    field_param: &FieldParam,
    username: &str,
) -> Result<Field, sqlx::Error> {
    let model = model_select(tx, &field_param.model_name).await?;

    query!(
        "INSERT INTO field (
            name,
            model_id,
            is_primary,
            data_type,
            is_nullable,
            precision,
            scale,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date
        ) VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            $11,
            $12
        )",
        field_param.name,
        model.id,
        field_param.is_primary,
        field_param.data_type as DbxDataType,
        field_param.is_nullable,
        field_param.precision,
        field_param.scale,
        field_param.extra,
        username,
        Utc::now(),
        username,
        Utc::now(),
    )
    .execute(&mut **tx)
    .await?;

    // Pull the row
    let field = field_select(tx, &model.name, &field_param.name).await?;

    Ok(field)
}

/// Pull one field
pub async fn field_select(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    field_name: &str,
) -> Result<Field, sqlx::Error> {
    let field = query_as!(
        Field,
        "SELECT
            id,
            name,
            model_id,
            model_name,
            seq,
            is_primary,
            data_type AS \"data_type!: DbxDataType\",
            is_nullable,
            precision,
            scale,
            extra,
            created_by,
            created_date,
            modified_by,
            modified_date
        FROM (
            SELECT
                field.id,
                field.name,
                field.model_id,
                model.name AS \"model_name\",
                ROW_NUMBER() OVER (ORDER BY field.id) as \"seq\",
                field.is_primary,
                field.data_type,
                field.is_nullable,
                field.precision,
                field.scale,
                field.extra,
                field.created_by,
                field.created_date,
                field.modified_by,
                field.modified_date
            FROM
                field
            LEFT JOIN
                model
            ON
                field.model_id = model.id 
            WHERE
                model.name = $1
        ) wip
        WHERE
            name = $2",
        model_name,
        field_name,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(field)
}

/// Pull many fields by model
pub async fn field_select_by_model(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Vec<Field>, sqlx::Error> {
    let fields = query_as!(
        Field,
        "SELECT
            field.id,
            field.name,
            field.model_id,
            model.name AS \"model_name\",
            ROW_NUMBER() OVER (ORDER BY field.id) as \"seq\",
            field.is_primary,
            field.data_type AS \"data_type!: DbxDataType\",
            field.is_nullable,
            field.precision,
            field.scale,
            field.extra,
            field.created_by,
            field.created_date,
            field.modified_by,
            field.modified_date
        FROM
            field
        LEFT JOIN
            model
        on
            field.model_id = model.id 
        WHERE
            model.name = $1
        ORDER BY
            field.id",
        model_name,
    )
    .fetch_all(&mut **tx)
    .await?;

    Ok(fields)
}

/// Update a field
pub async fn field_update(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    field_name: &str,
    field_param: &FieldParamUpdate,
    username: &str,
) -> Result<Field, sqlx::Error> {
    let model = model_select(tx, model_name).await?;

    let rows_affected = query!(
        "UPDATE
            field
        SET 
            name = $1,
            is_primary = $2,
            data_type = $3,
            is_nullable = $4,
            precision = $5,
            scale = $6,
            extra = $7,
            modified_by = $8,
            modified_date = $9
        WHERE
            model_id = $10
            AND name = $11",
        field_param.name,
        field_param.is_primary,
        field_param.data_type as DbxDataType,
        field_param.is_nullable,
        field_param.precision,
        field_param.scale,
        field_param.extra,
        username,
        Utc::now(),
        model.id,
        field_name,
    )
    .execute(&mut **tx)
    .await?
    .rows_affected();

    // Check if any rows were updated.
    if rows_affected == 0 {
        return Err(sqlx::Error::RowNotFound);
    }

    // Pull the row, but with the domain name added
    let field = field_select(tx, model_name, &field_param.name).await?;

    Ok(field)
}

/// Delete a field
pub async fn field_drop(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
    field_name: &str,
) -> Result<Field, sqlx::Error> {
    // Pull the row and parent
    let model = model_select(tx, model_name).await?;
    let field = field_select(tx, model_name, field_name).await?;

    // Now run the delete since we have the row in memory
    query!(
        "DELETE FROM
            field
        WHERE
            model_id = $1
            AND name = $2",
        model.id,
        field_name,
    )
    .execute(&mut **tx)
    .await?;

    Ok(field)
}

/// Delete all field for a model
pub async fn field_drop_by_model(
    tx: &mut Transaction<'_, Postgres>,
    model_name: &str,
) -> Result<Vec<Field>, sqlx::Error> {
    // Pull the rows and parent
    let model = model_select(tx, model_name).await?;
    let fields = field_select_by_model(tx, model_name).await?;

    // Now run the delete since we have the rows in memory
    query!(
        "DELETE FROM
            field
        WHERE
            model_id = $1",
        model.id,
    )
    .execute(&mut **tx)
    .await?;

    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use sqlx::PgPool;

    /// Create test domain
    fn gen_test_domain_parm(name: &str) -> DomainParam {
        DomainParam {
            name: name.to_string(),
            owner: format!("{}@test.com", name),
            extra: json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        }
    }

    /// Create test model
    fn gen_test_model_parm(name: &str, domain_name: &str) -> ModelParam {
        ModelParam {
            name: name.to_string(),
            domain_name: domain_name.to_string(),
            owner: format!("{}@test.com", name),
            extra: json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        }
    }

    /// Create test Field
    fn gen_test_field_parm(name: &str, model_name: &str) -> FieldParam {
        FieldParam {
            name: name.to_string(),
            model_name: model_name.to_string(),
            is_primary: false,
            data_type: DbxDataType::Decimal,
            is_nullable: true,
            precision: Some(8),
            scale: Some(2),
            extra: json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        }
    }

    impl FieldParam {
        /// Turn FieldParam into FieldParamUpdate
        fn into_update(self) -> FieldParamUpdate {
            FieldParamUpdate {
                name: self.name,
                is_primary: self.is_primary,
                data_type: self.data_type,
                is_nullable: self.is_nullable,
                precision: self.precision,
                scale: self.scale,
                extra: self.extra,
            }
        }
    }

    /// Test create domain
    #[sqlx::test]
    async fn test_domain_insert(pool: PgPool) {
        let domain = {
            let domain_param = gen_test_domain_parm("test_domain");

            let mut tx = pool.begin().await.unwrap();
            let domain = domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();

            domain
        };

        assert_eq!(domain.id, 1);
        assert_eq!(domain.name, "test_domain");
        assert_eq!(domain.owner, "test_domain@test.com");
        assert_eq!(
            domain.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(domain.created_by, "test");
        assert_eq!(domain.modified_by, "test");
    }

    /// Test double domain create conflict
    #[sqlx::test]
    async fn test_domain_insert_conflict(pool: PgPool) {
        let domain_param = gen_test_domain_parm("test_domain");

        {
            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "duplicate key value violates unique constraint \"domain_name_key\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test domain select
    #[sqlx::test]
    async fn test_domain_select(pool: PgPool) {
        {
            let domain_param = gen_test_domain_parm("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let domain = {
            let mut tx = pool.begin().await.unwrap();
            domain_select(&mut tx, "test_domain").await.unwrap()
        };

        assert_eq!(domain.id, 1);
        assert_eq!(domain.name, "test_domain");
        assert_eq!(domain.owner, "test_domain@test.com");
        assert_eq!(
            domain.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(domain.created_by, "test");
        assert_eq!(domain.modified_by, "test");
    }

    /// Test Reading a domain that does not exists
    #[sqlx::test]
    async fn test_domain_select_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_select(&mut tx, "test_domain").await.unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test domain search
    #[sqlx::test]
    async fn test_domain_search(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let domain_param = gen_test_domain_parm("foobar_domain");
            domain_insert(&mut tx, &domain_param, "foobar")
                .await
                .unwrap();

            tx.commit().await.unwrap();
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let domains = domain_select_search(&mut tx, &None, &None, &None, &None, &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 2);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let domains = domain_select_search(
                &mut tx,
                &Some("abcdef".to_string()),
                &None,
                &None,
                &None,
                &None,
            )
            .await
            .unwrap();

            assert_eq!(domains.len(), 0);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let domains = domain_select_search(
                &mut tx,
                &Some("test".to_string()),
                &None,
                &None,
                &None,
                &None,
            )
            .await
            .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let domains = domain_select_search(
                &mut tx,
                &Some("test".to_string()),
                &Some("test.com".to_string()),
                &None,
                &None,
                &None,
            )
            .await
            .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let domains = domain_select_search(
                &mut tx,
                &Some("test".to_string()),
                &Some("test.com".to_string()),
                &Some("abc".to_string()),
                &None,
                &None,
            )
            .await
            .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let domains = domain_select_search(&mut tx, &None, &None, &None, &Some(1), &None)
                .await
                .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "test_domain");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let domains = domain_select_search(&mut tx, &None, &None, &None, &Some(1), &Some(1))
                .await
                .unwrap();

            assert_eq!(domains.len(), 1);
            assert_eq!(domains[0].name, "foobar_domain");
        }
    }

    /// Test domain update
    #[sqlx::test]
    async fn test_domain_update(pool: PgPool) {
        {
            let domain_param = gen_test_domain_parm("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let domain = {
            let domain_param = gen_test_domain_parm("foobar_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_update(&mut tx, "test_domain", &domain_param, "foobar")
                .await
                .unwrap()
        };

        assert_eq!(domain.id, 1);
        assert_eq!(domain.name, "foobar_domain");
        assert_eq!(domain.owner, "foobar_domain@test.com");
        assert_eq!(
            domain.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(domain.created_by, "test");
        assert_eq!(domain.modified_by, "foobar");
    }

    /// Test domain update where no domain found
    #[sqlx::test]
    async fn test_domain_update_not_found(pool: PgPool) {
        let err = {
            let domain_param = gen_test_domain_parm("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_update(&mut tx, "test_domain", &domain_param, "test")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test domain update with conflict
    #[sqlx::test]
    async fn test_domain_update_conflict(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let domain_param = gen_test_domain_parm("foobar_domain");
            domain_insert(&mut tx, &domain_param, "foobar")
                .await
                .unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let domain_param = gen_test_domain_parm("foobar_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_update(&mut tx, "test_domain", &domain_param, "foobar")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "duplicate key value violates unique constraint \"domain_name_key\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test domain drop
    #[sqlx::test]
    async fn test_domain_drop(pool: PgPool) {
        {
            let domain_param = gen_test_domain_parm("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let domain = {
            let mut tx = pool.begin().await.unwrap();
            let domain = domain_drop(&mut tx, "test_domain").await.unwrap();

            tx.commit().await.unwrap();

            domain
        };

        assert_eq!(domain.id, 1);
        assert_eq!(domain.name, "test_domain");
        assert_eq!(domain.owner, "test_domain@test.com");
        assert_eq!(
            domain.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(domain.created_by, "test");
        assert_eq!(domain.modified_by, "test");

        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_select(&mut tx, "test_domain").await.unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test domain drop if not exists
    #[sqlx::test]
    async fn test_domain_drop_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_drop(&mut tx, "test_domain").await.unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test domain drop if children not droppped
    #[sqlx::test]
    async fn test_domain_drop_conflict(pool: PgPool) {
        {
            let domain_param = gen_test_domain_parm("test_domain");
            let model_param = gen_test_model_parm("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();
            domain_drop(&mut tx, "test_domain").await.unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "update or delete on table \"domain\" violates foreign key constraint \"model_domain_id_fkey\" on table \"model\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test create model
    #[sqlx::test]
    async fn test_model_insert(pool: PgPool) {
        let model = {
            let domain_param = gen_test_domain_parm("test_domain");
            let model_param = gen_test_model_parm("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();
            let model = model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();

            model
        };

        assert_eq!(model.id, 1);
        assert_eq!(model.name, "test_model");
        assert_eq!(model.domain_id, 1);
        assert_eq!(model.domain_name, "test_domain");
        assert_eq!(model.owner, "test_model@test.com");
        assert_eq!(
            model.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(model.created_by, "test");
        assert_eq!(model.modified_by, "test");
    }

    /// Test model insert where no domain found
    #[sqlx::test]
    async fn test_model_insert_not_found(pool: PgPool) {
        let err = {
            let model_param = gen_test_model_parm("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_insert(&mut tx, &model_param, "test")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test double model create conflict
    #[sqlx::test]
    async fn test_model_insert_conflict(pool: PgPool) {
        let model_param = gen_test_model_parm("test_model", "test_domain");

        {
            let domain_param = gen_test_domain_parm("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_insert(&mut tx, &model_param, "test")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "duplicate key value violates unique constraint \"model_name_key\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test model select
    #[sqlx::test]
    async fn test_model_select(pool: PgPool) {
        {
            let domain_param = gen_test_domain_parm("test_domain");
            let model_param = gen_test_model_parm("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let model = {
            let mut tx = pool.begin().await.unwrap();
            model_select(&mut tx, "test_model").await.unwrap()
        };

        assert_eq!(model.id, 1);
        assert_eq!(model.name, "test_model");
        assert_eq!(model.domain_id, 1);
        assert_eq!(model.domain_name, "test_domain");
        assert_eq!(model.owner, "test_model@test.com");
        assert_eq!(
            model.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(model.created_by, "test");
        assert_eq!(model.modified_by, "test");
    }

    /// Test Reading a model that does not exists
    #[sqlx::test]
    async fn test_model_select_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_select(&mut tx, "test_model").await.unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test model select by domain
    #[sqlx::test]
    async fn test_model_select_by_domain(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_by_domain(&mut tx, "test_domain")
                .await
                .unwrap();

            assert_eq!(models.len(), 0);
        }

        {
            let domain_param = gen_test_domain_parm("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_by_domain(&mut tx, "test_domain")
                .await
                .unwrap();

            assert_eq!(models.len(), 0);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model2", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_by_domain(&mut tx, "test_domain")
                .await
                .unwrap();

            assert_eq!(models.len(), 2);
        }
    }

    /// Test model search
    #[sqlx::test]
    async fn test_model_search(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model2", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let domain_param = gen_test_domain_parm("foobar_domain");
            domain_insert(&mut tx, &domain_param, "foobar")
                .await
                .unwrap();

            let model_param = gen_test_model_parm("foobar_model", "foobar_domain");
            model_insert(&mut tx, &model_param, "foobar").await.unwrap();

            tx.commit().await.unwrap();
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_search(&mut tx, &None, &None, &None, &None, &None, &None)
                .await
                .unwrap();

            assert_eq!(models.len(), 3);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model2");
            assert_eq!(models[2].name, "foobar_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_search(
                &mut tx,
                &Some("abcdef".to_string()),
                &None,
                &None,
                &None,
                &None,
                &None,
            )
            .await
            .unwrap();

            assert_eq!(models.len(), 0);
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_search(
                &mut tx,
                &Some("model".to_string()),
                &None,
                &None,
                &None,
                &None,
                &None,
            )
            .await
            .unwrap();

            assert_eq!(models.len(), 3);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model2");
            assert_eq!(models[2].name, "foobar_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_search(
                &mut tx,
                &Some("model2".to_string()),
                &None,
                &None,
                &None,
                &None,
                &None,
            )
            .await
            .unwrap();

            assert_eq!(models.len(), 1);
            assert_eq!(models[0].name, "test_model2");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_search(
                &mut tx,
                &None,
                &Some("test".to_string()),
                &None,
                &None,
                &None,
                &None,
            )
            .await
            .unwrap();

            assert_eq!(models.len(), 2);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model2");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_search(
                &mut tx,
                &None,
                &None,
                &Some("test_model%@test.com".to_string()),
                &None,
                &None,
                &None,
            )
            .await
            .unwrap();

            assert_eq!(models.len(), 2);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model2");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_search(
                &mut tx,
                &None,
                &None,
                &None,
                &Some("abc".to_string()),
                &None,
                &None,
            )
            .await
            .unwrap();

            assert_eq!(models.len(), 3);
            assert_eq!(models[0].name, "test_model");
            assert_eq!(models[1].name, "test_model2");
            assert_eq!(models[2].name, "foobar_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let models = model_select_search(&mut tx, &None, &None, &None, &None, &Some(1), &None)
                .await
                .unwrap();

            assert_eq!(models.len(), 1);
            assert_eq!(models[0].name, "test_model");
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let models =
                model_select_search(&mut tx, &None, &None, &None, &None, &Some(1), &Some(1))
                    .await
                    .unwrap();

            assert_eq!(models.len(), 1);
            assert_eq!(models[0].name, "test_model2");
        }
    }

    /// Test model update
    #[sqlx::test]
    async fn test_model_update(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let domain_param = gen_test_domain_parm("foobar_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let model = {
            let model_param = gen_test_model_parm("foobar_model", "foobar_domain");

            let mut tx = pool.begin().await.unwrap();
            model_update(&mut tx, "test_model", &model_param, "foobar")
                .await
                .unwrap()
        };

        assert_eq!(model.id, 1);
        assert_eq!(model.name, "foobar_model");
        assert_eq!(model.domain_id, 2);
        assert_eq!(model.domain_name, "foobar_domain");
        assert_eq!(model.owner, "foobar_model@test.com");
        assert_eq!(
            model.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(model.created_by, "test");
        assert_eq!(model.modified_by, "foobar");
    }

    /// Test model update where no domain or model found
    #[sqlx::test]
    async fn test_model_update_not_found(pool: PgPool) {
        {
            let domain_param = gen_test_domain_parm("test_domain");

            let mut tx = pool.begin().await.unwrap();
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let model_param = gen_test_model_parm("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_update(&mut tx, "test_model", &model_param, "test")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };

        {
            let model_param = gen_test_model_parm("test_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let model_param = gen_test_model_parm("test_model", "foobar_domain");

            let mut tx = pool.begin().await.unwrap();
            model_update(&mut tx, "test_model", &model_param, "foobar")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test model update with conflict
    #[sqlx::test]
    async fn test_model_update_conflict(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("foobar_model", "test_domain");
            model_insert(&mut tx, &model_param, "foobar").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let model_param = gen_test_model_parm("foobar_model", "test_domain");

            let mut tx = pool.begin().await.unwrap();
            model_update(&mut tx, "test_model", &model_param, "foobar")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "duplicate key value violates unique constraint \"model_name_key\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test model drop
    #[sqlx::test]
    async fn test_model_drop(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let model = {
            let mut tx = pool.begin().await.unwrap();
            let model = model_drop(&mut tx, "test_model").await.unwrap();

            tx.commit().await.unwrap();

            model
        };

        assert_eq!(model.id, 1);
        assert_eq!(model.name, "test_model");
        assert_eq!(model.domain_id, 1);
        assert_eq!(model.domain_name, "test_domain");
        assert_eq!(model.owner, "test_model@test.com");
        assert_eq!(
            model.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(model.created_by, "test");
        assert_eq!(model.modified_by, "test");

        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_select(&mut tx, "test_domain").await.unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test model drop if not exists
    #[sqlx::test]
    async fn test_model_drop_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_drop(&mut tx, "test_model").await.unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test model drop if children not droppped
    #[sqlx::test]
    async fn test_model_drop_conflict(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();
            model_drop(&mut tx, "test_model").await.unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "update or delete on table \"model\" violates foreign key constraint \"field_model_id_fkey\" on table \"field\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test create field
    #[sqlx::test]
    async fn test_field_insert(pool: PgPool) {
        let field = {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            let field = field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();

            field
        };

        assert_eq!(field.id, 1);
        assert_eq!(field.name, "test_field");
        assert_eq!(field.model_id, 1);
        assert_eq!(field.model_name, "test_model");
        assert_eq!(field.seq, Some(1));
        assert_eq!(field.is_primary, false);
        assert_eq!(field.data_type, DbxDataType::Decimal);
        assert_eq!(field.is_nullable, true);
        assert_eq!(field.precision, Some(8));
        assert_eq!(field.scale, Some(2));
        assert_eq!(
            field.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field.created_by, "test");
        assert_eq!(field.modified_by, "test");
    }

    /// Test field insert where no model found
    #[sqlx::test]
    async fn test_field_insert_not_found(pool: PgPool) {
        let err = {
            let field_param = gen_test_field_parm("test_field", "test_model");

            let mut tx = pool.begin().await.unwrap();
            field_insert(&mut tx, &field_param, "test")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test double field create conflict
    #[sqlx::test]
    async fn test_field_insert_conflict(pool: PgPool) {
        let field_param = gen_test_field_parm("test_field", "test_model");

        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_insert(&mut tx, &field_param, "test")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "duplicate key value violates unique constraint \"field_model_id_name_key\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test field select
    #[sqlx::test]
    async fn test_field_select(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let field = {
            let mut tx = pool.begin().await.unwrap();
            field_select(&mut tx, "test_model", "test_field")
                .await
                .unwrap()
        };

        assert_eq!(field.id, 1);
        assert_eq!(field.name, "test_field");
        assert_eq!(field.model_id, 1);
        assert_eq!(field.model_name, "test_model");
        assert_eq!(field.seq, Some(1));
        assert_eq!(field.is_primary, false);
        assert_eq!(field.data_type, DbxDataType::Decimal);
        assert_eq!(field.is_nullable, true);
        assert_eq!(field.precision, Some(8));
        assert_eq!(field.scale, Some(2));
        assert_eq!(
            field.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field.created_by, "test");
        assert_eq!(field.modified_by, "test");
    }

    /// Test Reading a field that does not exists
    #[sqlx::test]
    async fn test_field_select_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_select(&mut tx, "test_field", "test_model")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test field select by model
    #[sqlx::test]
    async fn test_field_select_by_model(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();
            let fields = field_select_by_model(&mut tx, "test_model").await.unwrap();

            assert_eq!(fields.len(), 0);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let fields = field_select_by_model(&mut tx, "test_model").await.unwrap();

            assert_eq!(fields.len(), 0);
        }

        {
            let mut tx = pool.begin().await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field2", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        {
            let mut tx = pool.begin().await.unwrap();
            let fields = field_select_by_model(&mut tx, "test_model").await.unwrap();

            assert_eq!(fields.len(), 2);
        }
    }

    /// Test field update
    #[sqlx::test]
    async fn test_field_update(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            let domain_param = gen_test_domain_parm("foobar_domain");
            domain_insert(&mut tx, &domain_param, "foobar")
                .await
                .unwrap();

            let model_param = gen_test_model_parm("foobar_model", "foobar_domain");
            model_insert(&mut tx, &model_param, "foobar").await.unwrap();

            tx.commit().await.unwrap();
        }

        let field = {
            let field_param = gen_test_field_parm("foobar_field", "test_model");

            let mut tx = pool.begin().await.unwrap();
            field_update(
                &mut tx,
                "test_model",
                "test_field",
                &field_param.into_update(),
                "foobar",
            )
            .await
            .unwrap()
        };

        assert_eq!(field.id, 1);
        assert_eq!(field.name, "foobar_field");
        assert_eq!(field.model_id, 1);
        assert_eq!(field.model_name, "test_model");
        assert_eq!(field.seq, Some(1));
        assert_eq!(field.is_primary, false);
        assert_eq!(field.data_type, DbxDataType::Decimal);
        assert_eq!(field.is_nullable, true);
        assert_eq!(field.precision, Some(8));
        assert_eq!(field.scale, Some(2));
        assert_eq!(
            field.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field.created_by, "test");
        assert_eq!(field.modified_by, "foobar");
    }

    /// Test field update where no field or model found
    #[sqlx::test]
    async fn test_field_update_not_found(pool: PgPool) {
        let err = {
            let field_param = gen_test_field_parm("test_field", "test_model");

            let mut tx = pool.begin().await.unwrap();
            field_update(
                &mut tx,
                "test_model",
                "test_field",
                &field_param.into_update(),
                "test",
            )
            .await
            .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };

        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let field_param = gen_test_field_parm("foobar_field", "test_model");

            let mut tx = pool.begin().await.unwrap();
            field_update(
                &mut tx,
                "test_model",
                "test_field",
                &field_param.into_update(),
                "foobar",
            )
            .await
            .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test field update with conflict
    #[sqlx::test]
    async fn test_field_update_conflict(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("foobar_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let err = {
            let mut tx = pool.begin().await.unwrap();

            let field_param = gen_test_field_parm("foobar_field", "test_model");
            field_update(
                &mut tx,
                "test_model",
                "test_field",
                &field_param.into_update(),
                "foobar",
            )
            .await
            .unwrap_err()
        };

        match err {
            sqlx::Error::Database(err) => assert_eq!(
                err.message().to_string(),
                "duplicate key value violates unique constraint \"field_model_id_name_key\"",
            ),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test field drop
    #[sqlx::test]
    async fn test_field_drop(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let field = {
            let mut tx = pool.begin().await.unwrap();
            let field = field_drop(&mut tx, "test_model", "test_field")
                .await
                .unwrap();

            tx.commit().await.unwrap();

            field
        };

        assert_eq!(field.id, 1);
        assert_eq!(field.name, "test_field");
        assert_eq!(field.model_id, 1);
        assert_eq!(field.model_name, "test_model");
        assert_eq!(field.seq, Some(1));
        assert_eq!(field.is_primary, false);
        assert_eq!(field.data_type, DbxDataType::Decimal);
        assert_eq!(field.is_nullable, true);
        assert_eq!(field.precision, Some(8));
        assert_eq!(field.scale, Some(2));
        assert_eq!(
            field.extra,
            json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        );
        assert_eq!(field.created_by, "test");
        assert_eq!(field.modified_by, "test");

        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_select(&mut tx, "test_model", "test_field")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test field drop if not exists
    #[sqlx::test]
    async fn test_field_drop_not_found(pool: PgPool) {
        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_drop(&mut tx, "test_model", "test_field")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }

    /// Test field drop by model
    #[sqlx::test]
    async fn test_field_drop_by_model(pool: PgPool) {
        {
            let mut tx = pool.begin().await.unwrap();

            let domain_param = gen_test_domain_parm("test_domain");
            domain_insert(&mut tx, &domain_param, "test").await.unwrap();

            let model_param = gen_test_model_parm("test_model", "test_domain");
            model_insert(&mut tx, &model_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            let field_param = gen_test_field_parm("test_field2", "test_model");
            field_insert(&mut tx, &field_param, "test").await.unwrap();

            tx.commit().await.unwrap();
        }

        let fields = {
            let mut tx = pool.begin().await.unwrap();
            let fields = field_drop_by_model(&mut tx, "test_model").await.unwrap();

            tx.commit().await.unwrap();

            fields
        };

        assert_eq!(fields.len(), 2);

        let err = {
            let mut tx = pool.begin().await.unwrap();
            field_select(&mut tx, "test_model", "test_field")
                .await
                .unwrap_err()
        };

        match err {
            sqlx::Error::RowNotFound => (),
            err => panic!("Incorrect sqlx error type: {}", err),
        };
    }
}
