use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{prelude::BASE64_STANDARD, Engine};
use rand::Rng;
use crate::error::ServerError;
use crate::error::ServerError::BadRequest;

fn build_keys(key_iv_base64: &str) -> Result<([u8; 32], [u8; 16]), ServerError> {
    let key_iv_base64_vec = key_iv_base64.split(":$:").collect::<Vec<&str>>();
    if key_iv_base64_vec.len() != 2 {
        BadRequest("Invalid key_iv_base64".to_string());
    }

    let key_base64 = key_iv_base64_vec[0];
    let iv_base64 = key_iv_base64_vec[1];

    let key_decoded: Vec<u8> = BASE64_STANDARD
        .decode(key_base64.as_bytes())
        .map_err(|ex| BadRequest(format!("Error decoding key_base64: {}", ex)))?;
    let key: [u8; 32] = key_decoded.try_into().map_err(|ex| {
        BadRequest(format!("Error converting key_decoded to [u8; 32]: {:?}", ex))
    })?;

    let iv_decoded: Vec<u8> = BASE64_STANDARD
        .decode(iv_base64.as_bytes())
        .map_err(|ex| BadRequest(format!("Error decoding iv_base64: {}", ex)))?;
    let iv: [u8; 16] = iv_decoded.try_into().map_err(|ex| {
        BadRequest(format!("Error converting iv_decoded to [u8; 16]: {:?}", ex))
    })?;
    Ok((key, iv))
}

pub(super) fn encryption(
    key_iv_base64: &str,
    plaintext: &str,
) -> Result<String, ServerError> {
    let (key, iv) = build_keys(key_iv_base64)?;

    let plaintext_bin: Vec<u8> = plaintext.as_bytes().to_vec();
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let mut buf = vec![0u8; plaintext_bin.len() + 16];
    let pt_len = plaintext_bin.len();
    buf[..pt_len].copy_from_slice(&plaintext_bin);
    let ct = Aes256CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .map_err(|ex| BadRequest(format!("Error encrypting: {}", ex)))?;
    let ct_base64 = format!("enc:$:AES256CBC:$:{}", BASE64_STANDARD.encode(&ct));
    Ok(ct_base64)
}

pub(super) fn decryption(
    key_iv_base64: &str,
    prefix_encrypted_text_base64: &str,
) -> Result<String, ServerError> {
    let (key, iv) = build_keys(key_iv_base64)?;

    let prefix_encrypted_text_base64_split =
        prefix_encrypted_text_base64.split("$:").collect::<Vec<&str>>();

    if prefix_encrypted_text_base64_split.len() != 3
        && prefix_encrypted_text_base64_split[1] != "AES256CBC"
    {
        return Err(BadRequest(
            "Invalid data, it should start with enc:$:AES256CBC:$:".to_string(),
        ));
    }

    let encrypted_text_decoded: Vec<u8> =
        BASE64_STANDARD.decode(prefix_encrypted_text_base64_split[2].as_bytes()).unwrap();
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
    println!("{:?}", generate_key());
    let key_base64 =
        "5jcK7IMk3+QbNLikFRl3Zwgl9xagKD87s5dT2UqaSR4=:$:5jcK7IMk3+QbNLikFRl3Zw==".to_string(); //gitleaks:allow
    let plaintext = "Hello, World!".to_string();
    let encrypted_text = "enc:$:AES256CBC:$:yQp5HF92QfpV/jdmPIDYJQ==".to_string();
    let enc = encryption(&key_base64, &plaintext).expect("Error encrypting");
    println!("Encrypted: value: {}", enc);
    assert_eq!(enc, encrypted_text);
    let dec = decryption(&key_base64, &enc).expect("Error decrypting");
    println!("Decrypted: value: {}", dec);
    assert_eq!(dec, plaintext);
}

pub(super) fn generate_key() -> String {
    let mut rng = rand::rng();
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    let mut iv = [0u8; 16];
    rng.fill(&mut iv);
    format!("{}:$:{}", BASE64_STANDARD.encode(key), BASE64_STANDARD.encode(iv))
}
