use serde_json::Value;

#[derive(Clone, Debug)]
pub(crate) struct Authentication {
    authentication_type: String,
    authentication_details: Value,
}

pub(crate) enum AuthenticationError {
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
    pub(crate) fn new(authentication: crate::configuration::Authentication) -> Authentication {
        match authentication.authentication_type.as_str() {
            "admin_api_key" => Authentication {
                authentication_type: "admin_api_key".to_string(),
                authentication_details: authentication.authentication_details,
            },
            _ => panic!("Unsupported storage type"),
        }
    }

    pub(crate) async fn is_authorized(
        &self,
        auth_token: Option<String>,
        _uri: String,
        resource: String,
    ) -> Result<bool, AuthenticationError> {
        if resource == "/health" || resource == "/unlock" {
            return Ok(true);
        }
        let mut is_authorized = false;
        if self.authentication_type == "admin_api_key" {
            let admin_api_key = self.authentication_details["api_key"].as_str();
            let admin_api_key = match admin_api_key {
                Some(key) => key,
                None => {
                    return Err(AuthenticationError::Error(
                        "No Api key configured in the server".to_string(),
                    ))
                }
            };
            let auth_token = match auth_token {
                Some(token) => token,
                None => {
                    return Ok(false);
                }
            };
            if auth_token == admin_api_key {
                is_authorized = true;
            }
        }
        Ok(is_authorized)
    }
}
