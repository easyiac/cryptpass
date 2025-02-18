use serde_json::Value;

#[derive(Clone, Debug)]
pub struct Authentication {
    authentication_type: String,
    authentication_details: Value,
}

pub enum AuthenticationError {
    Error(String),
}

impl std::fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AuthenticationError::Error(e) => write!(f, "Error: {}", e),
        }
    }
}

impl Authentication {
    pub fn new(authentication: crate::configuration::Authentication) -> Authentication {
        match authentication.authentication_type.as_str() {
            "admin_api_key" => Authentication {
                authentication_type: "admin_api_key".to_string(),
                authentication_details: authentication.authentication_details,
            },
            _ => panic!("Unsupported storage type"),
        }
    }

    pub fn is_authorized(
        &self,
        auth_token: Option<String>,
        _uri: String,
        resource: String,
    ) -> Result<bool, AuthenticationError> {
        if resource == "/health" {
            return Ok(true);
        }
        let mut is_authorized = false;
        if self.authentication_type == "admin_api_key" {
            let auth_token = match auth_token {
                Some(token) => token,
                None => {
                    return Ok(false);
                }
            };
            let admin_api_key = self.authentication_details["api_key"].as_str();
            let admin_api_key = match admin_api_key {
                Some(key) => key,
                None => {
                    return Err(AuthenticationError::Error(
                        "No Api key configured in the server".to_string(),
                    ))
                }
            };
            if auth_token == admin_api_key {
                is_authorized = true;
            }
        }
        Ok(is_authorized)
    }
}
