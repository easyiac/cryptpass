use crate::error::CryptPassError;

pub(crate) mod aes256;
pub(crate) mod sha256;

pub(crate) fn encrypt(key_iv_base64: &str, plaintext: &str) -> Result<String, CryptPassError> {
    aes256::encryption(key_iv_base64, plaintext)
}

pub(crate) fn decrypt(
    key_iv_base64: &str,
    encrypted_text_base64: &str,
) -> Result<String, CryptPassError> {
    aes256::decryption(key_iv_base64, encrypted_text_base64)
}

pub(crate) fn generate_key() -> String {
    aes256::generate_key()
}

pub(crate) fn hash(data: &str) -> String {
    sha256::encode(data)
}

pub(crate) fn match_hash(data: &str, hash: &str) -> bool {
    sha256::match_hash(data, hash)
}
