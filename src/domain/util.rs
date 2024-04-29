#[cfg(test)]
pub mod test_utils {
    use crate::domain::core::DomainParam;
    use serde_json::json;

    /// Create test domain
    pub fn gen_test_domain_param(name: &str) -> DomainParam {
        DomainParam {
            name: name.to_string(),
            owner: format!("{}@test.com", name),
            extra: json!({
                "abc": 123,
                "def": [1, 2, 3],
            }),
        }
    }
}
