use vartalaap_core::Engine;
use vartalaap_identity::{Identity, Profile};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let n: u64 = rand::random();
    p.push(format!("vart-audit-{tag}-{n}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

// (a) Profile with an avatar round-trips through the store and self-verifies.
#[test]
fn profile_with_avatar_roundtrips() {
    let dir = tmpdir("avatar");
    let e = Engine::open(&dir, "pw").unwrap();
    let avatar: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    e.set_profile(Profile {
        display_name: "Asha".into(),
        bio: "hi".into(),
        status: "online".into(),
        avatar: Some(avatar.clone()),
        updated_at: 123,
    })
    .unwrap();
    // Reopen a fresh Engine -> forces load + verify path.
    drop(e);
    let e2 = Engine::open(&dir, "pw").unwrap();
    let got = e2.profile().expect("profile() must not error").expect("present");
    assert_eq!(got.avatar.as_deref(), Some(avatar.as_slice()));
    std::fs::remove_dir_all(&dir).ok();
}

// (b) Wrong-length identity bytes -> CorruptIdentity, surfaced not panic.
#[test]
fn wrong_length_identity_is_corrupt_error() {
    let dir = tmpdir("wronglen");
    {
        let _e = Engine::open(&dir, "pw").unwrap(); // creates 32-byte identity
    }
    // Now overwrite the stored identity secret with 31 bytes via a low-level Store.
    // We emulate corruption by opening store directly.
    use vartalaap_crypto::{derive_key, VaultKey};
    use vartalaap_store::Store;
    let salt = std::fs::read(dir.join("kdf.salt")).unwrap();
    let mut s16 = [0u8; 16];
    s16.copy_from_slice(&salt);
    let key = VaultKey::from(*derive_key("pw", &s16));
    let store = Store::open(&dir.join("vault.redb"), key).unwrap();
    store.put_secret("identity_sk", &[1u8; 31]).unwrap();
    drop(store);

    let r = Engine::open(&dir, "pw");
    match r {
        Err(e) => eprintln!("wrong-len -> error: {e}"),
        Ok(_) => panic!("expected error on wrong-length identity"),
    }
    std::fs::remove_dir_all(&dir).ok();
}

// (c) Wrong passphrase on second open: salt exists, key differs -> identity decrypt fails (AEAD).
#[test]
fn wrong_passphrase_second_open() {
    let dir = tmpdir("wrongpw");
    let id_a = {
        let e = Engine::open(&dir, "right").unwrap();
        e.vartalaap_id()
    };
    let r = Engine::open(&dir, "wrong");
    match &r {
        Err(e) => eprintln!("wrong-pw -> error: {e}"),
        Ok(eng) => eprintln!("wrong-pw -> OK, id={} (was {})", eng.vartalaap_id(), id_a),
    }
    std::fs::remove_dir_all(&dir).ok();
}

// (d) Interrupted first run: salt written but identity never persisted -> new identity silently.
#[test]
fn salt_without_identity_makes_new_identity() {
    let dir = tmpdir("partial");
    // Simulate: create salt + empty vault, but no identity stored.
    use vartalaap_crypto::{derive_key, VaultKey};
    use vartalaap_store::Store;
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&[7u8; 16]);
    std::fs::write(dir.join("kdf.salt"), salt).unwrap();
    let key = VaultKey::from(*derive_key("pw", &salt));
    let store = Store::open(&dir.join("vault.redb"), key).unwrap();
    drop(store); // vault exists but no identity_sk

    let e = Engine::open(&dir, "pw").unwrap();
    eprintln!("partial first-run produced id: {}", e.vartalaap_id());
    std::fs::remove_dir_all(&dir).ok();
}

// (e) zeroize check: identity_seed returns a plain [u8;32] copy (not zeroized).
#[test]
fn identity_seed_is_plain_copy() {
    let id = Identity::generate();
    let s1 = *id.secret_bytes();
    let s2 = *id.secret_bytes();
    assert_eq!(s1, s2);
}
