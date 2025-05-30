use sha2::{Digest, Sha256};

pub(crate) fn encode(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("SHA256:$:{}", hex::encode(hasher.finalize()))
}

pub(crate) fn match_hash(data: &str, hash: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let hex_string = hex::encode(hasher.finalize());
    hash == format!("SHA256:$:{}", hex_string)
}
