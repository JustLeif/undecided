const SERVICE: &str = "software.xes.client";
const DEVICE_KEY_ACCOUNT: &str = "device-encryption-key";

#[cfg(target_os = "android")]
pub fn create_device_encryption_key() -> Result<(), String> {}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn create_device_encryption_key() -> Result<(), String> {
    use apple_native_keyring_store::protected::{AccessPolicy, Cred};
    use rand::TryRng;
    use zeroize::Zeroizing;
    let mut key = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut key)
        .expect("OS CSPRNG failed to generate a key. If this happens, the device cannot use this application.");
    let key = Zeroizing::new(key);
    let entry = Cred::build(
        SERVICE,
        DEVICE_KEY_ACCOUNT,
        AccessPolicy::RequireUserPresence,
        None,
        false,
    )
    .map_err(|error| format!("{error}"))?;
    entry
        .set_secret(key.as_slice())
        .map_err(|error| format!("{error}"))?;
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn device_encrypt(
    plaintext: zeroize::Zeroizing<Vec<u8>>,
) -> Result<(Vec<u8>, [u8; 12]), String> {
    use aes_gcm::{
        aead::{Aead, Generate, KeyInit},
        Aes256Gcm, Nonce,
    };
    use apple_native_keyring_store::protected::{AccessPolicy, Cred};
    use zeroize::Zeroizing;
    let entry = Cred::build(
        SERVICE,
        DEVICE_KEY_ACCOUNT,
        AccessPolicy::RequireUserPresence,
        None,
        false,
    )
    .map_err(|error| format!("{error}"))?;
    let key = Zeroizing::new(entry.get_secret().map_err(|error| format!("{error}"))?);
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|error| format!("{error}"))?;
    let nonce = Nonce::generate();
    Ok((
        cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|error| format!("{error}"))?,
        nonce.into(),
    ))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn device_decrypt(
    ciphertext: Vec<u8>,
    nonce_bytes: [u8; 12],
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use apple_native_keyring_store::protected::{AccessPolicy, Cred};
    use zeroize::Zeroizing;
    let entry = Cred::build(
        SERVICE,
        DEVICE_KEY_ACCOUNT,
        AccessPolicy::RequireUserPresence,
        None,
        false,
    )
    .map_err(|error| format!("{error}"))?;
    let key = Zeroizing::new(entry.get_secret().map_err(|error| format!("{error}"))?);
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|error| format!("{error}"))?;
    let nonce = Nonce::from(nonce_bytes);
    Ok(Zeroizing::new(
        cipher
            .decrypt(&nonce, ciphertext.as_ref())
            .map_err(|error| format!("{error}"))?,
    ))
}
