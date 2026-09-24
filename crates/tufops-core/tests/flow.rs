//! A repository's life cycle with in-memory keys and storage.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{Duration, SubsecRound, Utc};
use tuf::client::{Client, Config as ClientConfig};
use tuf::crypto::{EcdsaPrivateKey, HashAlgorithm, PrivateKey, PublicKey, SignatureScheme};
use tuf::metadata::{
    MetadataPath, MetadataVersion, RawSignedMetadata, TargetDescription, TargetPath,
};
use tuf::pouf::Pouf1;
use tuf::repository::{EphemeralRepository, RepositoryStorage};
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

    fn public_url(&self, name: &str) -> String {
        format!("https://example.test/{name}")
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

/// A repository signed by one online key, delegating each `(role, path)`.
fn delegating_config(key: &TestKey, delegations: &[(&str, &str)]) -> Result<Config> {
    let role = |name: &str, paths: &str| {
        format!(
            "[roles.{name}]\nkeys = [\"online\"]\nthreshold = 1\nexpires_days = 30\n\
             signing_days = 7\n{paths}\n"
        )
    };
    let mut text = [
        "storage = \"gs://bucket\"\n[keys.online]\nonline = \"gcpkms:k\"\n".to_owned(),
        format!("public_key = \"\"\"{}\"\"\"\n", key.pem()),
        ["root", "targets", "snapshot", "timestamp"]
            .map(|r| role(r, ""))
            .concat(),
    ]
    .concat();
    for (name, path) in delegations {
        text += &role(name, &format!("paths = [\"{path}\"]"));
    }
    Config::parse(&text)
}

/// Publishes `repo`, then looks up `paths` with rust-tuf's client, the way TUF clients do.
async fn client_finds(repo: &Repo, store: &MemStore, paths: &[&str]) -> Vec<bool> {
    publish::publish(repo, store).await.unwrap();
    let remote = EphemeralRepository::<Pouf1>::new();
    let objects = store.0.lock().unwrap().clone();
    for (name, data) in objects {
        let Some(file) = name
            .strip_prefix("metadata/")
            .and_then(|f| f.strip_suffix(".json"))
        else {
            continue;
        };
        let (version, role) = match file.split_once('.') {
            Some((v, role)) => (MetadataVersion::Number(v.parse().unwrap()), role),
            None => (MetadataVersion::None, file),
        };
        let path = MetadataPath::new(role.to_owned()).unwrap();
        remote
            .store_metadata(&path, version, &mut &data[..])
            .await
            .unwrap();
    }
    let root = RawSignedMetadata::new(repo.root_history().unwrap()[0].to_vec());
    let local = EphemeralRepository::new();
    let mut client = Client::with_trusted_root(ClientConfig::default(), &root, local, remote)
        .await
        .unwrap();
    client.update().await.unwrap();
    let mut found = vec![];
    for path in paths {
        let path = TargetPath::new(*path).unwrap();
        found.push(client.fetch_target_description(&path).await.is_ok());
    }
    found
}

#[tokio::test]
async fn delegated_paths() {
    let key = TestKey::new();
    let now = Utc::now();
    let store = MemStore::default();
    let target = |path: &str| {
        let desc = TargetDescription::from_slice(path.as_bytes(), &[HashAlgorithm::Sha256]);
        (TargetPath::new(path).unwrap(), desc.unwrap())
    };
    let publish = async |repo: &mut Repo, config: &Config| {
        repo.update_online(config, None, now).unwrap();
        let roles: Vec<_> = repo.roles().map(str::to_owned).collect();
        sign_all(repo, &Repo::default(), &roles, &[&key]).await;
    };
    let changes = |status: &EventStatus, role: &str| -> Vec<String> {
        let role = status.roles.iter().find(|r| r.role == role).unwrap();
        role.changes.iter().map(|c| c.to_string()).collect()
    };
    let paths = ["a/x", "b/y", "b/one/p", "b/two/q", "z"];

    // Each target goes in the role its path belongs in, and clients find them all.
    let config = delegating_config(&key, &[("alpha", "a/"), ("beta", "b/")]).unwrap();
    let mut repo = Repo::default();
    repo.apply_config(&config, None, &Repo::default(), now)
        .unwrap();
    let files: Vec<_> = paths.map(target).into();
    for (path, desc) in &files {
        store
            .put(&target_object(path, desc).unwrap(), vec![])
            .await
            .unwrap();
    }
    let changed = repo
        .add_targets(&config, &repo.clone(), files, now)
        .unwrap();
    assert_eq!(changed, ["alpha", "beta", "targets"]);
    publish(&mut repo, &config).await;
    assert_eq!(client_finds(&repo, &store, &paths).await, [true; 5]);

    // Moving alpha from a/ to c/ moves a/x to the top-level targets, where clients still find it.
    let config = delegating_config(&key, &[("alpha", "c/"), ("beta", "b/")]).unwrap();
    let main = repo.clone();
    let changed = repo.apply_config(&config, None, &main, now).unwrap();
    assert_eq!(changed, ["targets", "alpha"]);
    let status = EventStatus::new(&config, &main, &repo).unwrap();
    assert!(
        changes(&status, "targets").contains(&"1 target moved here unchanged from alpha".into())
    );
    assert_eq!(
        changes(&status, "alpha"),
        ["1 target moved unchanged to targets"]
    );
    publish(&mut repo, &config).await;
    assert_eq!(client_finds(&repo, &store, &paths).await, [true; 5]);

    // Delegating a path moves the targets under it out of the top-level targets.
    let config = delegating_config(&key, &[("alpha", "z"), ("beta", "b/")]).unwrap();
    let main = repo.clone();
    assert_eq!(
        repo.apply_config(&config, None, &main, now).unwrap(),
        ["targets", "alpha"]
    );
    assert_eq!(
        repo.role_for_target(&TargetPath::new("z").unwrap())
            .unwrap(),
        "alpha"
    );
    publish(&mut repo, &config).await;
    assert_eq!(client_finds(&repo, &store, &paths).await, [true; 5]);

    // Replacing beta with two roles that split its paths moves its targets into them, and what
    // neither covers into the top-level targets: none are lost.
    let split = [
        ("alpha", "z"),
        ("beta-one", "b/one/"),
        ("beta-two", "b/two/"),
    ];
    let config = delegating_config(&key, &split).unwrap();
    let main = repo.clone();
    let changed = repo.apply_config(&config, None, &main, now).unwrap();
    assert_eq!(changed, ["beta", "targets", "beta-one", "beta-two"]);
    let status = EventStatus::new(&config, &main, &repo).unwrap();
    assert_eq!(
        changes(&status, "beta-one"),
        ["1 target moved here unchanged from beta"]
    );
    assert!(changes(&status, "targets").contains(&"delegation beta removed".into()));
    assert!(
        changes(&status, "targets").contains(&"1 target moved here unchanged from beta".into())
    );
    publish(&mut repo, &config).await;
    assert_eq!(client_finds(&repo, &store, &paths).await, [true; 5]);

    // Paths that more than one role covers are rejected; a mere common prefix is fine.
    for overlapping in ["b/", "b/sub/", "b/file"] {
        let err = delegating_config(&key, &[("alpha", overlapping), ("beta", "b/")]);
        let err = err.err().unwrap();
        assert!(
            format!("{err:#}").contains("overlap"),
            "{overlapping}: {err:#}"
        );
    }
    delegating_config(&key, &[("alpha", "bb/"), ("beta", "b/")]).unwrap();
}
