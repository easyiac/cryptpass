use crate::error::{CryptPassError, CryptPassErrorDetails};

/// Macro to create a CryptPassError with CryptPassErrorDetails
/// 
/// # Arguments
/// 
/// * `error_type` - The type of error (BadRequest, InternalServerError, etc.)
/// * `error_msg` - The error message
/// * `correlation_id` - The correlation ID (Option<String>)
/// * `caused_by` - Optional caused_by message (defaults to None)
/// 
/// # Examples
/// 
/// ```
/// let correlation_id = Some("123".to_string());
/// return Err(cryptpass_error!(BadRequest, "Invalid key_iv_base64", correlation_id));
/// 
/// // With caused_by
/// return Err(cryptpass_error!(BadRequest, "Error decoding", correlation_id, ex.to_string()));
/// ```
#[macro_export]
macro_rules! cryptpass_error {
    // Without caused_by
    ($error_type:ident, $error_msg:expr, $correlation_id:expr) => {
        CryptPassError::$error_type(CryptPassErrorDetails {
            error: $error_msg.to_string(),
            correlation_id: $correlation_id,
            caused_by: None,
        })
    };
    
    // With caused_by
    ($error_type:ident, $error_msg:expr, $correlation_id:expr, $caused_by:expr) => {
        CryptPassError::$error_type(CryptPassErrorDetails {
            error: $error_msg.to_string(),
            correlation_id: $correlation_id,
            caused_by: Some($caused_by.to_string()),
        })
    };
}