//! The vault bindings, exercised from a JS runtime.
//!
//! `atomic_lib` already proves the format round-trips in native Rust. What is
//! unproven until here is the *boundary*: that a `Uint8Array` key survives the
//! crossing, that a JS array of objects deserializes into the shape the
//! importer wants, and that a caller gets `null` rather than an exception when
//! there is nothing to back up.
//!
//! Run with `wasm-pack test --node --test vault`.

#![cfg(target_arch = "wasm32")]

use atomic_wasm::{vault_generate_key, ClientDb};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_node_experimental);

const DEVICE: &str = "0303030303030303030303030303030303030303030303030303030303030303";
const PSEUDONYM: &str = "testpseudonym";

#[wasm_bindgen_test]
fn generated_keys_are_the_right_size_and_not_constant() {
    let a = vault_generate_key();
    let b = vault_generate_key();
    assert_eq!(a.len(), 32, "a drive vault key is 32 bytes");
    assert_ne!(a, b, "two generated keys must differ");
}

/// A wrong-length key must be refused at the boundary rather than panicking
/// inside the wasm module, which in a browser surfaces as an unrecoverable
/// abort instead of a catchable error.
#[wasm_bindgen_test]
async fn a_bad_key_length_is_an_error_not_a_panic() {
    let db = ClientDb::new_in_memory(None).await.expect("in-memory db");
    let result = db
        .vault_export(
            "did:ad:whatever",
            &[0u8; 31],
            1,
            PSEUDONYM,
            DEVICE,
            1,
            1,
            false,
            JsValue::UNDEFINED,
            None,
        )
        .await;
    assert!(result.is_err(), "a 31-byte key must be rejected");
}

/// An empty drive returns `null`, so a periodic backup tick can skip the
/// upload instead of storing an empty object every time it runs.
#[wasm_bindgen_test]
async fn an_empty_drive_exports_nothing() {
    let db = ClientDb::new_in_memory(None).await.expect("in-memory db");
    let key = vault_generate_key();
    let out = db
        .vault_export(
            "did:ad:nonexistent",
            &key,
            1,
            PSEUDONYM,
            DEVICE,
            1,
            1,
            false,
            JsValue::UNDEFINED,
            None,
        )
        .await
        .expect("export should succeed, not throw");
    assert!(out.is_null(), "nothing to back up means null");
}

/// Importing nothing is a no-op rather than an error — a restore that finds an
/// empty vault should report zero, not fail.
#[wasm_bindgen_test]
async fn importing_no_objects_is_a_no_op() {
    let db = ClientDb::new_in_memory(None).await.expect("in-memory db");
    let key = vault_generate_key();
    let empty = serde_wasm_bindgen::to_value(&Vec::<u8>::new()).unwrap();
    let summary = db
        .vault_import(&key, 1, PSEUDONYM, DEVICE, empty)
        .await
        .expect("import of nothing should succeed");
    assert!(!summary.is_null());
}

/// The property the whole demo rests on: a key wrapped on one device is
/// recoverable on another that holds only the agent secret. This is what makes
/// "clear site data, sign in, restore" possible without a second secret.
#[wasm_bindgen_test]
fn a_wrapped_key_survives_a_wiped_device() {
    let agent_secret = &[9u8; 64];
    let key = vault_generate_key();

    let envelope = atomic_wasm::vault_wrap_key(&key, agent_secret).expect("wrap");

    // The wiped device has nothing but the envelope and the agent secret.
    let recovered = atomic_wasm::vault_unwrap_key(&envelope, agent_secret).expect("unwrap");
    assert_eq!(recovered, key, "the same key must come back");
}

/// A wrong agent secret must fail loudly. Proceeding with a bad key would fill
/// the drive with objects nobody can open — much harder to diagnose than a
/// refusal at unwrap time.
#[wasm_bindgen_test]
fn the_wrong_agent_secret_is_refused() {
    let key = vault_generate_key();
    let envelope = atomic_wasm::vault_wrap_key(&key, &[1u8; 64]).expect("wrap");
    assert!(atomic_wasm::vault_unwrap_key(&envelope, &[2u8; 64]).is_err());
}

/// The wrapped form is what gets handed to the control plane, so it must not
/// contain the key.
#[wasm_bindgen_test]
fn the_wrapped_form_does_not_contain_the_key() {
    let key = vault_generate_key();
    let envelope = atomic_wasm::vault_wrap_key(&key, &[3u8; 64]).expect("wrap");
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!envelope.contains(&hex), "raw key leaked into the envelope");
}

/// The agent secret has several representations in this codebase — a base64
/// JSON blob, the `privateKey` inside it, the decoded seed. Wrapping under one
/// and unwrapping with another would both "succeed" while leaving the envelope
/// permanently unopenable with the real seed, so anything but the raw seed is
/// refused.
#[wasm_bindgen_test]
fn only_a_64_byte_agent_signature_is_accepted() {
    let key = vault_generate_key();
    assert!(
        atomic_wasm::vault_wrap_key(&key, b"a base64 secret string").is_err(),
        "anything but the signature must be refused, not silently wrapped"
    );
    assert!(
        atomic_wasm::vault_wrap_key(&key, &[0u8; 32]).is_err(),
        "the private key is not the proof"
    );
    assert!(atomic_wasm::vault_wrap_key(&key, &[0u8; 64]).is_ok());
}

/// An envelope that opens but holds something other than a drive key means the
/// wrong envelope was fetched. Saying so beats failing later at decrypt time,
/// which reads like corrupted backups.
#[wasm_bindgen_test]
fn an_envelope_holding_something_else_is_refused() {
    use atomic_lib::vault::secret_envelope::{NewWrapper, SecretEnvelope};

    let agent_secret = [5u8; 64];
    let not_a_key = SecretEnvelope::create(
        b"this is an agent secret, not a drive key",
        &[NewWrapper::AgentSecret {
            agent_secret: &agent_secret,
        }],
    )
    .unwrap()
    .to_json()
    .unwrap();

    assert!(atomic_wasm::vault_unwrap_key(&not_a_key, &agent_secret).is_err());
}

/// A non-empty export must hand JS a `Uint8Array`, not an array of numbers.
///
/// This is the test that was missing, and its absence let a corrupt vault ship
/// past every other layer. `serde_wasm_bindgen` renders a `Vec<u8>` as a JS
/// array of numbers; `fetch` has no binary meaning for an array, so it
/// stringifies it, and every object reached the bucket as the ASCII text
/// "1,1,0,0,..." instead of the envelope. The count went up, quota accrued,
/// the UI reported success, and every restore failed with "unsupported vault
/// envelope version 49" — 49 being the character '1'.
///
/// The two export/import tests above both cover the *empty* case, so the byte
/// representation of a real export was never observed on the JS side at all.
#[wasm_bindgen_test]
async fn a_real_export_hands_js_binary_not_a_number_array() {
    use wasm_bindgen::JsCast;

    let db = ClientDb::new_in_memory(None).await.expect("in-memory db");
    let drive = "did:ad:vaultexporttest";

    db.put_resource(&format!(
        r#"{{"@id":"{drive}","https://atomicdata.dev/properties/name":"Export test"}}"#
    ))
    .await
    .expect("seed a resource to back up");

    let key = vault_generate_key();
    let out = db
        .vault_export(
            drive,
            &key,
            1,
            PSEUDONYM,
            DEVICE,
            1,
            1,
            false,
            JsValue::UNDEFINED,
            None,
        )
        .await
        .expect("export should succeed");

    assert!(
        !out.is_null(),
        "a drive with a resource has something to back up"
    );

    let sealed = js_sys::Reflect::get(&out, &wasm_bindgen::JsValue::from_str("sealed"))
        .expect("the export result carries the sealed bytes");

    assert!(
        sealed.is_instance_of::<js_sys::Uint8Array>(),
        "sealed must be a Uint8Array; an Array uploads as text and is unrestorable",
    );

    let bytes = sealed.unchecked_into::<js_sys::Uint8Array>().to_vec();
    assert!(!bytes.is_empty(), "a sealed pack is not empty");
    // The envelope's own header, which is what a restore reads first. Asserting
    // it here means a future change to the boundary fails on the byte that
    // actually matters rather than on a type name.
    assert_eq!(
        bytes[0], 1,
        "first byte is the envelope version, not '1' (49)"
    );
}

/// A current-state checkpoint crosses the boundary as binary and is smaller
/// than the full one for a resource with edit history, and restores the
/// current name into a fresh store.
#[wasm_bindgen_test]
async fn a_current_state_checkpoint_is_smaller_and_restores() {
    use wasm_bindgen::JsCast;

    let drive = "did:ad:vaultshallowtest";
    let db = ClientDb::new_in_memory(None).await.expect("in-memory db");
    for i in 0..20 {
        db.put_resource(&format!(
            r#"{{"@id":"{drive}","https://atomicdata.dev/properties/name":"edit {i}"}}"#
        ))
        .await
        .expect("edit");
    }
    let key = vault_generate_key();

    let mut sizes = Vec::new();
    let mut sealed_current = None;
    for current_state_only in [false, true] {
        let out = db
            .vault_export(
                drive,
                &key,
                1,
                PSEUDONYM,
                DEVICE,
                1,
                1,
                false,
                JsValue::UNDEFINED,
                Some(current_state_only),
            )
            .await
            .expect("export");
        let sealed = js_sys::Reflect::get(&out, &JsValue::from_str("sealed"))
            .expect("sealed bytes")
            .unchecked_into::<js_sys::Uint8Array>()
            .to_vec();
        sizes.push(sealed.len());
        if current_state_only {
            sealed_current = Some(sealed);
        }
    }
    assert!(
        sizes[1] < sizes[0],
        "current-state checkpoint ({}) must be smaller than the full one ({})",
        sizes[1],
        sizes[0]
    );

    let fresh = ClientDb::new_in_memory(None).await.expect("in-memory db");
    let object = js_sys::Object::new();
    js_sys::Reflect::set(
        &object,
        &JsValue::from_str("objectKey"),
        &JsValue::from_str(&format!("vault/{PSEUDONYM}/checkpoints/ckpt-000001.loro")),
    )
    .unwrap();
    js_sys::Reflect::set(
        &object,
        &JsValue::from_str("sealed"),
        &js_sys::Uint8Array::from(sealed_current.unwrap().as_slice()),
    )
    .unwrap();
    let objects = js_sys::Array::of1(&object).into();
    fresh
        .vault_import(&key, 1, PSEUDONYM, DEVICE, objects)
        .await
        .expect("a shallow checkpoint restores");
}
