use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{prelude::BASE64_STANDARD, Engine};

#[allow(dead_code)]
pub(crate) async fn encryption(key_base64: &str, iv_base64: &str, plaintext: &str) -> String {
    let key_decoded: Vec<u8> = BASE64_STANDARD.decode(key_base64.as_bytes()).unwrap();
    let key: [u8; 32] = key_decoded.try_into().unwrap();

    let iv_decoded: Vec<u8> = BASE64_STANDARD.decode(iv_base64.as_bytes()).unwrap();
    let iv: [u8; 16] = iv_decoded.try_into().unwrap();

    let plaintext_bin: Vec<u8> = plaintext.as_bytes().to_vec();
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let mut buf = vec![0u8; plaintext_bin.len() + 16];
    let pt_len = plaintext_bin.len();
    buf[..pt_len].copy_from_slice(&plaintext_bin);
    let ct = Aes256CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .unwrap();
    let ct_base64 = BASE64_STANDARD.encode(&ct);
    ct_base64.to_string()
}

#[allow(dead_code)]
pub(crate) async fn decryption(
    key_base64: &str,
    iv_base64: &str,
    encrypted_text_base64: &str,
) -> String {
    let key_decoded: Vec<u8> = BASE64_STANDARD.decode(key_base64.as_bytes()).unwrap();
    let key: [u8; 32] = key_decoded.try_into().unwrap();

    let iv_decoded: Vec<u8> = BASE64_STANDARD.decode(iv_base64.as_bytes()).unwrap();
    let iv: [u8; 16] = iv_decoded.try_into().unwrap();

    let encrypted_text_decoded: Vec<u8> =
        BASE64_STANDARD.decode(encrypted_text_base64.as_bytes()).unwrap();
    let encrypted_text_bin: Vec<u8> = encrypted_text_decoded.to_vec();
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let mut buf = vec![0u8; encrypted_text_bin.len()];
    let pt = Aes256CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(&encrypted_text_bin, &mut buf)
        .unwrap();
    let pt_str = String::from_utf8_lossy(&pt);
    pt_str.to_string()
}

#[tokio::test]
async fn test() {
    let key_base64 = "***REMOVED***".to_string();
    let iv_base64 = "5jcK7IMk3+QbNLikFRl3Zw==".to_string();
    let plaintext = "Hello, World!".to_string();
    let encrypted_text = "yQp5HF92QfpV/jdmPIDYJQ==".to_string();
    let enc = encryption(&key_base64, &iv_base64, &plaintext).await;
    println!("Encrypted: value: {}", enc);
    assert_eq!(enc, encrypted_text);
    let dec = decryption(&key_base64, &iv_base64, &enc).await;
    println!("Decrypted: value: {}", dec);
    assert_eq!(dec, plaintext);
}
