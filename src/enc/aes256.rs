use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{prelude::BASE64_STANDARD, Engine};

#[allow(dead_code)]
pub(crate) async fn encryption(
    key_str_base64: &String,
    iv_str_base64: &String,
    plaintext: &String,
) -> String {
    let key_decoded: Vec<u8> = BASE64_STANDARD.decode(key_str_base64.as_bytes()).unwrap();
    let key: [u8; 32] = key_decoded.try_into().unwrap();

    let iv_decoded: Vec<u8> = BASE64_STANDARD.decode(iv_str_base64.as_bytes()).unwrap();
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
    key_str_base64: &String,
    iv_str_base64: &String,
    encrypted_text_base64: &String,
) -> String {
    let key_decoded: Vec<u8> = BASE64_STANDARD.decode(key_str_base64.as_bytes()).unwrap();
    let key: [u8; 32] = key_decoded.try_into().unwrap();

    let iv_decoded: Vec<u8> = BASE64_STANDARD.decode(iv_str_base64.as_bytes()).unwrap();
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
    let key_str_base64 = "***REMOVED***".to_string();
    let iv_str_base64 = "+0Vfhn16YpMKYQNOvnP/AA==".to_string();
    let plaintext = "hello world! this is my plaintext.".to_string();
    let encrypted_text =
        "d618sNKZ9ouOIn4M5IiIanT5T14cJTJMxJ0d9xmo/hRf+TtuHB6G6tIkzq4viTSo".to_string();
    let enc = encryption(&key_str_base64, &iv_str_base64, &plaintext).await;
    println!("{:?}", enc);
    assert_eq!(enc, encrypted_text);
    let dec = decryption(&key_str_base64, &iv_str_base64, &enc).await;
    println!("{:?}", dec);
    assert_eq!(dec, plaintext);
}
