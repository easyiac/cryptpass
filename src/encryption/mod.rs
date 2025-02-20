use crate::encryption::aes256::Aes256CbcEncError;

pub(crate) mod aes256;

pub(crate) async fn encryption(
    key_iv_base64: &str,
    plaintext: &str,
) -> Result<String, Aes256CbcEncError> {
    aes256::encryption(key_iv_base64, plaintext).await
}

pub(crate) async fn decryption(
    key_iv_base64: &str,
    encrypted_text_base64: &str,
) -> Result<String, Aes256CbcEncError> {
    aes256::decryption(key_iv_base64, encrypted_text_base64).await
}

pub(crate) async fn generate_key() -> String {
    aes256::generate_key().await
}
