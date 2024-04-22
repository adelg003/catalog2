use regex::Regex;
use validator::ValidationError;

/// Only allow for valid DBX name, meaning letters, number, dashes, and underscores. First
/// character needs to be a letter. Also, since DBX is case-insensitive, only allow lower
/// characters to ensure unique constraints work.
pub fn dbx_validater(obj_name: &str) -> Result<(), ValidationError> {
    let dbx_regex = Regex::new("^[a-z][a-z0-9_-]*$");
    match dbx_regex {
        Ok(re) if re.is_match(obj_name) => Ok(()),
        _ => Err(ValidationError::new("Failed DBX Regex Check")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test DBX Validater
    #[test]
    fn test_dbx_validator() {
        let failed_check = ValidationError::new("Failed DBX Regex Check");

        assert_eq!(dbx_validater("test_abc-123"), Ok(()));
        assert_eq!(dbx_validater("test_&"), Err(failed_check.clone()));
        assert_eq!(dbx_validater("123-test"), Err(failed_check.clone()));
        assert_eq!(dbx_validater(""), Err(failed_check));
    }
}
