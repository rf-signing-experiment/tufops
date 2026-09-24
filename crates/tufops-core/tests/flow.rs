//! A repository's life cycle with in-memory keys and storage.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{Duration, SubsecRound, Utc};
use tuf::crypto::{EcdsaPrivateKey, HashAlgorithm, PrivateKey, PublicKey, SignatureScheme};
use tuf::metadata::{TargetDescription, TargetPath};
use tufops_core::backend::{BlobStore, Signer};
use tufops_core::publish::{self, target_object};
use tufops_core::{Config, EventStatus, Repo};

struct TestKey(EcdsaPrivateKey);

impl TestKey {
    fn new() -> Self {
        let scheme = SignatureScheme::EcdsaSha2NistP256;
        let pkcs8 = EcdsaPrivateKey::pkcs8(&scheme).unwrap();
        Self(EcdsaPrivateKey::from_pkcs8(&pkcs8, scheme).unwrap())
    }

    fn pem(&self) -> String {
        self.0.public().to_pem().unwrap()
    }
}

#[async_trait]
impl Signer for TestKey {
    fn public_key(&self) -> &PublicKey {
        self.0.public()
    }

    async fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(self.0.sign(msg)?.value().as_bytes().to_vec())
    }
}

#[derive(Default)]
struct MemStore(Mutex<HashMap<String, Vec<u8>>>);

#[async_trait]
impl BlobStore for MemStore {
    async fn list(&self, prefix: &str) -> Result<HashMap<String, Vec<u8>>> {
        use md5::Digest;
        let objects = self.0.lock().unwrap();
        let listed = objects.iter().filter(|(name, _)| name.starts_with(prefix));
        Ok(listed
            .map(|(name, data)| (name.clone(), md5::Md5::digest(data).to_vec()))
            .collect())
    }

    async fn put(&self, name: &str, data: Vec<u8>) -> Result<()> {
        self.0.lock().unwrap().insert(name.to_owned(), data);
        Ok(())
    }

    async fn put_file(&self, name: &str, path: &Path) -> Result<()> {
        self.put(name, std::fs::read(path)?).await
    }
}

fn make_config(alice: &TestKey, bob: &TestKey, online: &TestKey, root_threshold: u32) -> Config {
    make_config_with(alice, bob, online, root_threshold, 365)
}

fn make_config_with(
    alice: &TestKey,
    bob: &TestKey,
    online: &TestKey,
    root_threshold: u32,
    root_days: u32,
) -> Config {
    Config::parse(&format!(
        r#"
storage = "gs://bucket/repo"

[keys.alice]
owner = "@alice"
public_key = """{}"""

[keys.bob]
owner = "@bob"
public_key = """{}"""

[keys.online]
online = "gcpkms:projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
public_key = """{}"""

[roles.root]
keys = ["alice", "bob"]
threshold = {root_threshold}
expires_days = {root_days}
signing_days = 60

[roles.targets]
keys = ["alice", "bob"]
threshold = 1
expires_days = 365
signing_days = 60

[roles.snapshot]
keys = ["online"]
threshold = 1
expires_days = 365
signing_days = 60

[roles.timestamp]
keys = ["online"]
threshold = 1
expires_days = 2
signing_days = 1

[roles.nightly]
keys = ["online"]
threshold = 1
expires_days = 30
signing_days = 7
paths = ["nightly/"]
"#,
        alice.pem(),
        bob.pem(),
        online.pem(),
    ))
    .unwrap()
}

async fn sign_all(repo: &mut Repo, base: &Repo, roles: &[String], keys: &[&TestKey]) {
    for role in roles {
        let missing = repo.missing_keys(base, role).unwrap();
        for key in keys.iter().filter(|k| missing.contains(k.public_key())) {
            repo.sign(role, *key).await.unwrap();
        }
    }
}

#[tokio::test]
async fn life_cycle() {
    let (alice, bob, online) = (TestKey::new(), TestKey::new(), TestKey::new());
    let config = make_config(&alice, &bob, &online, 2);
    let now = Utc::now();

    // Initial signing event: everything is new.
    let main = Repo::default();
    let mut head = main.clone();
    let changed = head.apply_config(&config, None, &main, now).unwrap();
    assert_eq!(changed, ["root", "targets", "nightly"]);
    sign_all(&mut head, &main, &changed, &[&online, &alice]).await;
    let status = EventStatus::new(&config, &main, &head).unwrap();
    assert!(!status.complete());
    let needs: Vec<_> = status
        .needs(bob.public_key().key_id())
        .iter()
        .map(|r| r.role.as_str())
        .collect();
    assert_eq!(needs, ["root"]);
    assert!(status.offline());
    sign_all(&mut head, &main, &changed, &[&bob]).await;
    let status = EventStatus::new(&config, &main, &head).unwrap();
    assert!(status.complete());
    let files = ["metadata/root.json".to_owned()];
    assert!(
        !status.merges_automatically(&files),
        "offline events go through a pull request"
    );

    // Merged into main: CI adds snapshot and timestamp, then publishes.
    let mut main = head;
    let online_changed = main.update_online(&config, None, now).unwrap();
    assert_eq!(online_changed, ["snapshot", "timestamp"]);
    sign_all(&mut main, &Repo::default(), &online_changed, &[&online]).await;
    let store = MemStore::default();
    let uploaded = publish::publish(&main, &store).await.unwrap();
    assert_eq!(uploaded.last().unwrap(), "metadata/timestamp.json");
    assert!(
        publish::publish(&main, &store).await.unwrap().is_empty(),
        "nothing changed"
    );

    // Adding a nightly build only needs the online key; the target must be uploaded first.
    let mut head = main.clone();
    let path = TargetPath::new("nightly/app.bin").unwrap();
    let desc = TargetDescription::from_slice(b"hello", &[HashAlgorithm::Sha256]).unwrap();
    let changed = head
        .add_targets(&config, &main, vec![(path.clone(), desc.clone())], now)
        .unwrap();
    assert_eq!(changed, ["nightly"]);
    sign_all(&mut head, &main, &changed, &[&online]).await;
    let status = EventStatus::new(&config, &main, &head).unwrap();
    assert!(status.complete());
    let files = ["metadata/nightly.json".to_owned()];
    assert!(
        status.merges_automatically(&files),
        "online-only events merge by themselves"
    );
    let files = ["metadata/nightly.json".to_owned(), "tufops.toml".to_owned()];
    assert!(
        !status.merges_automatically(&files),
        "config changes need review"
    );
    assert!(
        status.roles[0].changes[0]
            .to_string()
            .starts_with("target nightly/app.bin added (5 bytes, sha256 2cf24dba")
    );
    let mut main = head;
    let online_changed = main.update_online(&config, None, now).unwrap();
    sign_all(&mut main, &Repo::default(), &online_changed, &[&online]).await;
    assert!(
        publish::publish(&main, &store).await.is_err(),
        "target not uploaded"
    );
    store
        .put(&target_object(&path, &desc).unwrap(), b"hello".to_vec())
        .await
        .unwrap();
    publish::publish(&main, &store).await.unwrap();

    // Rotating root to a threshold of 1 needs the previous root's threshold of 2 as well.
    let config = make_config(&alice, &bob, &online, 1);
    let mut head = main.clone();
    let changed = head.apply_config(&config, None, &main, now).unwrap();
    assert_eq!(changed, ["root"]);
    sign_all(&mut head, &main, &changed, &[&alice]).await;
    assert!(!EventStatus::new(&config, &main, &head).unwrap().complete());
    sign_all(&mut head, &main, &changed, &[&bob]).await;
    assert!(EventStatus::new(&config, &main, &head).unwrap().complete());
    let mut main = head;
    let online_changed = main.update_online(&config, None, now).unwrap();
    sign_all(&mut main, &Repo::default(), &online_changed, &[&online]).await;
    publish::publish(&main, &store).await.unwrap();

    // Rotating the online key: root and targets change offline; roles the new key signs get
    // new versions even though their content is the same.
    let online2 = TestKey::new();
    let config = make_config(&alice, &bob, &online2, 1);
    let mut head = main.clone();
    let changed = head.apply_config(&config, None, &main, now).unwrap();
    assert_eq!(changed, ["root", "targets", "nightly"]);
    sign_all(&mut head, &main, &changed, &[&alice, &online2]).await;
    assert!(EventStatus::new(&config, &main, &head).unwrap().complete());
    let mut main = head;
    let online_changed = main.update_online(&config, None, now).unwrap();
    assert_eq!(online_changed, ["snapshot", "timestamp"]);
    sign_all(&mut main, &Repo::default(), &online_changed, &[&online2]).await;
    publish::publish(&main, &store).await.unwrap();

    // Changing how long root is valid for gives root a new version with the new expiry, which
    // its keys must sign; applying the same config again changes nothing more.
    let old_config = make_config(&alice, &bob, &online2, 1);
    let config = make_config_with(&alice, &bob, &online2, 1, 180);
    let mut head = main.clone();
    let changed = head
        .apply_config(&config, Some(&old_config), &main, now)
        .unwrap();
    assert_eq!(changed, ["root"]);
    let status = EventStatus::new(&config, &main, &head).unwrap();
    let root = &status.roles[0];
    assert_eq!(root.expires, now.trunc_subsecs(0) + Duration::days(180));
    assert!(root.changes.is_empty(), "only version and expiry change");
    assert!(!status.complete());
    let again = head
        .apply_config(&config, Some(&config), &main, now)
        .unwrap();
    assert!(again.is_empty());
    let config = old_config;

    // Two days later the timestamp is refreshed; after ten months, offline roles need signing.
    let later = now + Duration::days(2);
    assert_eq!(
        main.clone().update_online(&config, None, later).unwrap(),
        ["timestamp"]
    );
    let mut head = main.clone();
    let changed = head
        .apply_config(&config, None, &main, now + Duration::days(310))
        .unwrap();
    assert_eq!(changed, ["root", "targets", "nightly"]);
}
