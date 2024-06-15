#[cfg(test)]
pub mod test_utils {
    use crate::model::core::ModelParam;
    use serde_json::json;

    /// Create test model
    pub fn gen_test_model_param(name: &str, domain_name: &str) -> ModelParam {
        ModelParam {
            name: name.to_string(),
            domain_name: domain_name.to_string(),
            owner: format!("{name}@test.com"),
            extra: json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        }
    }
}
