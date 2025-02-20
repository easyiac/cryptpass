use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{prelude::BASE64_STANDARD, Engine};
use rand::Rng;

#[derive(Debug)]
pub(crate) struct Aes256CbcEncError(String);

impl std::fmt::Display for Aes256CbcEncError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Aes256CbcEncError: {}", self.0)
    }
}

async fn build_keys(key_iv_base64: &str) -> Result<([u8; 32], [u8; 16]), Aes256CbcEncError> {
    let key_iv_base64_vec = key_iv_base64.split(':').collect::<Vec<&str>>();
    if key_iv_base64_vec.len() != 3 {
        Aes256CbcEncError("Invalid key_iv_base64".to_string());
    }

    if key_iv_base64_vec[0] != "aes256" {
        Aes256CbcEncError("Invalid key_iv_base64".to_string());
    }

    let key_base64 = key_iv_base64_vec[1];
    let iv_base64 = key_iv_base64_vec[2];

    let key_decoded: Vec<u8> = BASE64_STANDARD
        .decode(key_base64.as_bytes())
        .map_err(|ex| Aes256CbcEncError(format!("Error decoding key_base64: {}", ex)))?;
    let key: [u8; 32] = key_decoded.try_into().map_err(|ex| {
        Aes256CbcEncError(format!("Error converting key_decoded to [u8; 32]: {:?}", ex))
    })?;

    let iv_decoded: Vec<u8> = BASE64_STANDARD
        .decode(iv_base64.as_bytes())
        .map_err(|ex| Aes256CbcEncError(format!("Error decoding iv_base64: {}", ex)))?;
    let iv: [u8; 16] = iv_decoded.try_into().map_err(|ex| {
        Aes256CbcEncError(format!("Error converting iv_decoded to [u8; 16]: {:?}", ex))
    })?;
    Ok((key, iv))
}

#[allow(dead_code)]
pub(super) async fn encryption(
    key_iv_base64: &str,
    plaintext: &str,
) -> Result<String, Aes256CbcEncError> {
    let (key, iv) = build_keys(key_iv_base64).await?;

    let plaintext_bin: Vec<u8> = plaintext.as_bytes().to_vec();
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let mut buf = vec![0u8; plaintext_bin.len() + 16];
    let pt_len = plaintext_bin.len();
    buf[..pt_len].copy_from_slice(&plaintext_bin);
    let ct = Aes256CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .map_err(|ex| Aes256CbcEncError(format!("Error encrypting: {}", ex)))?;
    let ct_base64 = BASE64_STANDARD.encode(&ct);
    Ok(ct_base64.to_string())
}

#[allow(dead_code)]
pub(super) async fn decryption(
    key_iv_base64: &str,
    encrypted_text_base64: &str,
) -> Result<String, Aes256CbcEncError> {
    let (key, iv) = build_keys(key_iv_base64).await?;

    let encrypted_text_decoded: Vec<u8> =
        BASE64_STANDARD.decode(encrypted_text_base64.as_bytes()).unwrap();
    let encrypted_text_bin: Vec<u8> = encrypted_text_decoded.to_vec();
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let mut buf = vec![0u8; encrypted_text_bin.len()];
    let pt = Aes256CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(&encrypted_text_bin, &mut buf)
        .unwrap();
    let pt_str = String::from_utf8_lossy(&pt);
    Ok(pt_str.to_string())
}

#[tokio::test]
async fn test() {
    println!("{:?}", generate_key().await);
    let key_base64 =
        "aes256:***REMOVED***:5jcK7IMk3+QbNLikFRl3Zw==".to_string();
    let plaintext = "Hello, World!".to_string();
    let encrypted_text = "yQp5HF92QfpV/jdmPIDYJQ==".to_string();
    let enc = encryption(&key_base64, &plaintext).await.expect("Error encrypting");
    println!("Encrypted: value: {}", enc);
    assert_eq!(enc, encrypted_text);
    let dec = decryption(&key_base64, &enc).await.expect("Error decrypting");
    println!("Decrypted: value: {}", dec);
    assert_eq!(dec, plaintext);
}

pub(super) async fn generate_key() -> String {
    let mut rng = rand::rng();
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    let mut iv = [0u8; 16];
    rng.fill(&mut iv);
    format!("aes256:{}:{}", BASE64_STANDARD.encode(key), BASE64_STANDARD.encode(iv))
}
