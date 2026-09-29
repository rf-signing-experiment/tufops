//! Publishing the repository to object storage.

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use md5::{Digest, Md5};
use tuf::Database;
use tuf::crypto::{HashAlgorithm, HashValue};
use tuf::metadata::{
    Metadata, MetadataPath, RawSignedMetadata, TargetDescription, TargetPath, TargetsMetadata,
    TimestampMetadata,
};
use tuf::pouf::Pouf1;

use crate::backend::BlobStore;
use crate::repo::{Repo, parse_unverified};

pub const METADATA_PREFIX: &str = "metadata/";
pub const TARGETS_PREFIX: &str = "targets/";
/// A web page summarizing the repository, published next to `metadata/` and `targets/`. It reads
/// the metadata in the browser, so it only changes with tufops itself.
pub const INDEX_PAGE: &str = "index.html";
/// The object clients start every update from.
const TIMESTAMP: &str = "metadata/timestamp.json";

/// A target's SHA-256, the hash tufops records and names uploads by.
pub fn target_sha256(desc: &TargetDescription) -> Result<&HashValue> {
    let hash = desc.hashes().get(&HashAlgorithm::Sha256);
    hash.context("target has no sha256")
}

/// Object name of a target file: consistent snapshots prefix the file name with its SHA-256.
pub fn target_object(path: &TargetPath, desc: &TargetDescription) -> Result<String> {
    let name = path.with_hash_prefix(target_sha256(desc)?)?;
    Ok(format!("{TARGETS_PREFIX}{name}"))
}

/// Checks the metadata the way a client would: the root chain from version 1, then timestamp,
/// snapshot, targets and delegated targets, including expiry.
pub fn verify(repo: &Repo) -> Result<()> {
    fn raw<M: Metadata>(bytes: &[u8]) -> RawSignedMetadata<Pouf1, M> {
        RawSignedMetadata::new(bytes.to_vec())
    }
    let now = Utc::now();

    let history = repo.root_history()?;
    let mut db = Database::<Pouf1>::from_trusted_root(&raw(history[0])).context("root v1")?;
    for (i, root) in history.iter().enumerate().skip(1) {
        db.update_root(&raw(root))
            .with_context(|| format!("root v{}", i + 1))?;
    }
    db.update_timestamp(&now, &raw(repo.require_raw("timestamp")?))
        .context("timestamp")?;
    db.update_snapshot(&now, &raw(repo.require_raw("snapshot")?))
        .context("snapshot")?;
    db.update_targets(&now, &raw(repo.require_raw("targets")?))
        .context("targets")?;
    for role in repo.targets_roles().iter().filter(|r| *r != "targets") {
        let path = MetadataPath::new(role.clone())?;
        let meta = raw(repo.require_raw(role)?);
        db.update_delegated_targets(&now, &MetadataPath::targets(), &path, &meta)
            .with_context(|| format!("role {role}"))?;
    }
    Ok(())
}

/// Object names and contents of the metadata as clients fetch it.
fn metadata_objects(repo: &Repo) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut objects = BTreeMap::new();
    for (i, root) in repo.root_history()?.into_iter().enumerate() {
        objects.insert(
            format!("{METADATA_PREFIX}{}.root.json", i + 1),
            root.to_vec(),
        );
    }
    for role in repo
        .targets_roles()
        .into_iter()
        .chain(["snapshot".to_owned()])
    {
        let (version, _) = repo.require_header(&role)?;
        objects.insert(
            format!("{METADATA_PREFIX}{version}.{role}.json"),
            repo.require_raw(&role)?.to_vec(),
        );
    }
    objects.insert(
        TIMESTAMP.to_owned(),
        repo.require_raw("timestamp")?.to_vec(),
    );
    Ok(objects)
}

/// Checks that publishing `repo` would not replace the published timestamp with an older
/// version, which clients that have the newer one reject as a rollback, or with a different one
/// of the same version, which means the metadata was published from a history that diverged.
async fn check_timestamp(repo: &Repo, store: &dyn BlobStore) -> Result<()> {
    let Some(published) = store.get(TIMESTAMP).await? else {
        return Ok(());
    };
    let parsed = parse_unverified::<TimestampMetadata>(&published);
    let published_version = parsed.context("parsing the published timestamp")?.version();
    let (version, _) = repo.require_header("timestamp")?;
    ensure!(
        published_version <= version,
        "storage has timestamp version {published_version}, newer than this repository's \
         {version}: publish from an up-to-date checkout of main"
    );
    ensure!(
        published_version < version || repo.raw("timestamp") == Some(&published[..]),
        "storage has a timestamp version {version} that differs from this repository's: it was \
         published from metadata that diverged from this checkout"
    );
    Ok(())
}

/// Verifies the repository, checks it is not older than what is published and that every target
/// file has been uploaded, then uploads the metadata objects and the summary page that are
/// missing or differ, timestamp last. Returns the objects uploaded.
pub async fn publish(repo: &Repo, store: &dyn BlobStore) -> Result<Vec<String>> {
    verify(repo)?;
    check_timestamp(repo, store).await?;

    let uploaded = store.list(TARGETS_PREFIX).await?;
    for role in repo.targets_roles() {
        let targets = repo.require::<TargetsMetadata>(&role)?;
        for (path, desc) in targets.targets() {
            let name = target_object(path, desc)?;
            ensure!(
                uploaded.contains_key(&name),
                "target {path} of {role} was never uploaded ({name})"
            );
        }
    }

    let mut published = store.list(METADATA_PREFIX).await?;
    published.extend(store.list(INDEX_PAGE).await?);
    let mut objects = metadata_objects(repo)?;
    objects.insert(INDEX_PAGE.to_owned(), include_bytes!("index.html").to_vec());
    let mut changed: Vec<_> = objects
        .into_iter()
        .filter(|(name, data)| {
            published
                .get(name)
                .is_none_or(|md5| md5[..] != Md5::digest(data)[..])
        })
        .collect();
    // Clients start from timestamp.json, so it must only refer to files already uploaded.
    changed.sort_by_key(|(name, _)| name == TIMESTAMP);
    let mut names = vec![];
    for (name, data) in changed {
        store.put(&name, data).await?;
        names.push(name);
    }
    Ok(names)
}
