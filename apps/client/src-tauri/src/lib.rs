use rand::TryRng;
use zeroize::Zeroizing;

const SERVICE: &str = "software.xes.client";
const DEVICE_KEY_ACCOUNT: &str = "device-encryption-key";

#[tauri::command]
fn set_keyring() {
    use apple_native_keyring_store::protected::{AccessPolicy, Cred};
    let entry = Cred::build(
        SERVICE,
        DEVICE_KEY_ACCOUNT,
        AccessPolicy::RequireUserPresence,
        None,
        false,
    )
    .unwrap();

    let mut key = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut key)
        .expect("OS CSPRNG failed to generate a key. If this happens, the device cannot use this application.");
    let key = Zeroizing::new(key);

    entry.set_secret(key.as_slice()).unwrap();
}

#[tauri::command]
fn get_keyring() -> Vec<u8> {
    use apple_native_keyring_store::protected::{AccessPolicy, Cred};
    let entry = Cred::build(
        SERVICE,
        DEVICE_KEY_ACCOUNT,
        AccessPolicy::RequireUserPresence,
        None,
        false,
    )
    .unwrap();

    entry.get_secret().unwrap()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![set_keyring, get_keyring])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
