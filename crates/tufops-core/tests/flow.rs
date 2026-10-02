//! A repository's life cycle with in-memory keys and storage.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Duration, SubsecRound, Utc};
use tuf::client::{Client, Config as ClientConfig};
use tuf::crypto::{EcdsaPrivateKey, HashAlgorithm, PrivateKey, PublicKey, SignatureScheme};
use tuf::metadata::{
    MetadataPath, MetadataVersion, RawSignedMetadata, TargetDescription, TargetPath,
};
use tuf::pouf::Pouf1;
use tuf::repository::{EphemeralRepository, RepositoryStorage};
use tufops_core::backend::{BlobStore, Signer};
use tufops_core::config::TOP_LEVEL_ROLES;
use tufops_core::publish::{self, target_object};
use tufops_core::repo::covers;
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

    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().get(name).cloned())
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

/// What CI does on main: starts the new versions of online roles due `at`, signed with `key`.
async fn ci_update(
    repo: &mut Repo,
    config: &Config,
    at: DateTime<Utc>,
    key: &TestKey,
) -> Vec<String> {
    let changed = repo.update_online(config, None, at).unwrap();
    sign_all(repo, &Repo::default(), &changed, &[key]).await;
    changed
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
    let changed = ci_update(&mut main, &config, now, &online).await;
    assert_eq!(changed, ["snapshot", "timestamp"]);
    let store = MemStore::default();
    let uploaded = publish::publish(&main, &store).await.unwrap();
    assert_eq!(uploaded.last().unwrap(), "metadata/timestamp.json");
    assert!(uploaded.contains(&"index.html".to_owned()));
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
    ci_update(&mut main, &config, now, &online).await;
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
    ci_update(&mut main, &config, now, &online).await;
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
    let changed = ci_update(&mut main, &config, now, &online2).await;
    assert_eq!(changed, ["snapshot", "timestamp"]);
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

    // Two days later the timestamp is refreshed. Once that is published, publishing never goes
    // back to the older timestamp, nor replaces it with another of the same version.
    let later = now + Duration::days(2);
    let refresh = async |at| {
        let mut repo = main.clone();
        let changed = ci_update(&mut repo, &config, at, &online2).await;
        assert_eq!(changed, ["timestamp"]);
        repo
    };
    let refreshed = refresh(later).await;
    let diverged = refresh(later + Duration::hours(1)).await;
    assert_eq!(
        publish::publish(&refreshed, &store).await.unwrap(),
        ["metadata/timestamp.json"]
    );
    for (repo, error) in [(&main, "newer than"), (&diverged, "diverged")] {
        let err = publish::publish(repo, &store).await.unwrap_err();
        assert!(format!("{err:#}").contains(error), "{err:#}");
    }
    assert!(
        publish::publish(&refreshed, &store)
            .await
            .unwrap()
            .is_empty()
    );

    // After ten months, offline roles need signing.
    let mut head = main.clone();
    let changed = head
        .apply_config(&config, None, &main, now + Duration::days(310))
        .unwrap();
    assert_eq!(changed, ["root", "targets", "nightly"]);
}

/// Config for online key `name`.
fn key_toml(name: &str, key: &TestKey) -> String {
    let pem = key.pem();
    format!("[keys.{name}]\nonline = \"gcpkms:{name}\"\npublic_key = \"\"\"{pem}\"\"\"\n")
}

/// Config for role `name`, signed by `key` alone, with `extra` settings such as its paths.
fn role_toml(name: &str, key: &str, extra: &str) -> String {
    format!(
        "[roles.{name}]\nkeys = [\"{key}\"]\nthreshold = 1\nexpires_days = 30\n\
         signing_days = 7\n{extra}\n"
    )
}

/// A repository signed by one online key, delegating each `(role, path)`.
fn delegating_config(key: &TestKey, delegations: &[(&str, &str)]) -> Result<Config> {
    let mut text = format!("storage = \"gs://bucket\"\n{}", key_toml("online", key));
    for role in TOP_LEVEL_ROLES {
        text += &role_toml(role, "online", "");
    }
    for (name, path) in delegations {
        text += &role_toml(name, "online", &format!("paths = [\"{path}\"]"));
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
            Some((v, role)) => (Some(MetadataVersion::new(v.parse().unwrap())), role),
            None => (None, file),
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
        .add_targets(&config, &repo.clone(), files.clone(), now)
        .unwrap();
    assert_eq!(changed, ["alpha", "beta", "targets"]);
    assert_eq!(repo.listed_targets().unwrap(), files.into_iter().collect());
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

    // Removing a directory and a file takes them out of whichever roles list them. Their uploads
    // stay, but clients no longer find them.
    let main = repo.clone();
    let remove = ["b/one/", "z", "nothing/"].map(|p| TargetPath::new(p).unwrap());
    let matches = |path: &TargetPath| remove.iter().any(|p| covers(p, path));
    let (changed, removed) = repo.remove_targets(&config, &main, matches, now).unwrap();
    assert_eq!(
        (changed, removed),
        (vec!["alpha".into(), "beta-one".into()], 2)
    );
    let status = EventStatus::new(&config, &main, &repo).unwrap();
    assert_eq!(changes(&status, "beta-one"), ["target b/one/p removed"]);
    publish(&mut repo, &config).await;
    let found = client_finds(&repo, &store, &paths).await;
    assert_eq!(found, [true, true, false, true, false]);
    let nothing = TargetPath::new("nothing/").unwrap();
    assert_eq!(
        repo.clone()
            .remove_targets(&config, &repo, |p| covers(&nothing, p), now)
            .unwrap()
            .1,
        0
    );
    let mut listed: Vec<_> = repo.listed_targets().unwrap().into_keys().collect();
    listed.sort();
    assert_eq!(
        listed,
        ["a/x", "b/two/q", "b/y"].map(|p| TargetPath::new(p).unwrap())
    );
}

/// Roles with paths under other roles' paths: each target goes in the role with the most
/// specific path covering it, and clients find it there.
#[tokio::test]
async fn nested_delegations() {
    let key = TestKey::new();
    let now = Utc::now();
    let store = MemStore::default();
    let target = |path: &str| {
        let desc = TargetDescription::from_slice(path.as_bytes(), &[HashAlgorithm::Sha256]);
        (TargetPath::new(path).unwrap(), desc.unwrap())
    };
    let role_of = |repo: &Repo, path: &str| {
        repo.role_for_target(&TargetPath::new(path).unwrap())
            .unwrap()
    };

    // By name, archive would come first and hide the roles under it from clients.
    let nested = [
        ("archive", "archive/"),
        ("recent", "archive/2026/"),
        ("today", "archive/2026/10/"),
        ("zfile", "archive/2026/notes"),
    ];
    let config = delegating_config(&key, &nested).unwrap();
    let order: Vec<_> = config.delegations().map(|(n, _)| n.as_str()).collect();
    assert_eq!(order, ["today", "zfile", "recent", "archive"]);

    let mut repo = Repo::default();
    repo.apply_config(&config, None, &Repo::default(), now)
        .unwrap();
    let paths = [
        "archive/x",
        "archive/2026/x",
        "archive/2026/10/x",
        "archive/2026/notes",
        "archive/2025/x",
    ];
    let files: Vec<_> = paths.map(target).into();
    for (path, desc) in &files {
        store
            .put(&target_object(path, desc).unwrap(), vec![])
            .await
            .unwrap();
    }
    repo.add_targets(&config, &repo.clone(), files, now)
        .unwrap();
    let roles = paths.map(|p| role_of(&repo, p));
    assert_eq!(roles, ["archive", "recent", "today", "zfile", "archive"]);
    repo.update_online(&config, None, now).unwrap();
    let roles: Vec<_> = repo.roles().map(str::to_owned).collect();
    sign_all(&mut repo, &Repo::default(), &roles, &[&key]).await;
    assert_eq!(client_finds(&repo, &store, &paths).await, [true; 5]);

    // Dropping the nested roles moves their targets back up to archive.
    let config = delegating_config(&key, &nested[..1]).unwrap();
    let main = repo.clone();
    repo.apply_config(&config, None, &main, now).unwrap();
    assert_eq!(paths.map(|p| role_of(&repo, p)), ["archive"; 5]);
    let mut listed: Vec<_> = repo.listed_targets().unwrap().into_keys().collect();
    listed.sort();
    let mut expected = paths.map(|p| TargetPath::new(p).unwrap());
    expected.sort();
    assert_eq!(listed, expected);

    // Two roles with the same path are rejected; a mere common prefix is fine.
    let err = delegating_config(&key, &[("alpha", "b/"), ("beta", "b/")]).unwrap_err();
    assert!(format!("{err:#}").contains("overlap"), "{err:#}");
    delegating_config(&key, &[("alpha", "bb/"), ("beta", "b/")]).unwrap();

    // So are roles that can't be ordered so each path is searched before the paths covering it.
    let mut text = format!("storage = \"gs://bucket\"\n{}", key_toml("online", &key));
    for role in TOP_LEVEL_ROLES {
        text += &role_toml(role, "online", "");
    }
    text += &role_toml("alpha", "online", "paths = [\"a/\", \"b/x/\"]");
    text += &role_toml("beta", "online", "paths = [\"b/\", \"a/x/\"]");
    let err = Config::parse(&text).unwrap_err();
    assert!(format!("{err:#}").contains("overlap"), "{err:#}");
}

/// A role signed by an online key that doesn't sign snapshot or timestamp: CI doesn't hold such
/// keys, so it never starts new versions of the role, or puts it in its signing event.
#[tokio::test]
async fn online_key_ci_lacks() {
    let (ci, tools) = (TestKey::new(), TestKey::new());
    let mut text = format!(
        "storage = \"gs://bucket\"\n{}{}",
        key_toml("ci", &ci),
        key_toml("tools", &tools)
    );
    for role in TOP_LEVEL_ROLES {
        text += &role_toml(role, "ci", "");
    }
    text += &role_toml("tools", "tools", "paths = [\"tools/\"]");
    let config = Config::parse(&text).unwrap();
    assert!(config.ci_signs("targets") && !config.ci_signs("tools"));

    let now = Utc::now();
    let mut main = Repo::default();
    let changed = main
        .apply_config(&config, None, &Repo::default(), now)
        .unwrap();
    sign_all(&mut main, &Repo::default(), &changed, &[&ci, &tools]).await;
    ci_update(&mut main, &config, now, &ci).await;

    // In their signing periods, CI starts new versions of the roles it signs, but not of tools.
    let later = now + Duration::days(24);
    let changed = ci_update(&mut main, &config, later, &ci).await;
    assert_eq!(changed, ["targets", "snapshot", "timestamp"]);

    // Applying the config renews tools too, but CI's signing event takes only the other roles.
    let mut head = main.clone();
    let expiring = head.apply_config(&config, None, &main, later).unwrap();
    assert_eq!(expiring, ["root", "tools"]);
    let event = main.with_roles_from(&head, &["root".to_owned()]);
    let status = EventStatus::new(&config, &main, &event).unwrap();
    let roles: Vec<_> = status.roles.iter().map(|r| r.role.as_str()).collect();
    assert_eq!(roles, ["root"]);
    assert_eq!(event.root_history().unwrap().len(), 2);
}
