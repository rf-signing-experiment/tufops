//! Cloud backends for keys and storage, chosen by URI so providers other than Google Cloud can
//! be added alongside it.

use std::collections::HashMap;

use anyhow::{Result, bail};
use tufops_core::backend::{BlobStore, Signer};
use tufops_core::{Config, Repo};

mod gcp;

/// Opens the storage at `url`, for example `gs://bucket/prefix`.
pub async fn open_store(url: &str) -> Result<Box<dyn BlobStore>> {
    if let Some(path) = url.strip_prefix("gs://") {
        return Ok(Box::new(gcp::Gcs::new(path).await?));
    }
    bail!("unsupported storage URL {url}: expected gs://bucket[/prefix]")
}

/// Opens the online key at `uri`, for example
/// `gcpkms:projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1`.
pub async fn open_signer(uri: &str) -> Result<Box<dyn Signer>> {
    if let Some(name) = uri.strip_prefix("gcpkms:") {
        return Ok(Box::new(gcp::KmsSigner::new(name).await?));
    }
    bail!("unsupported online key {uri}: expected gcpkms:<key version name>")
}

/// Signs `roles` with each configured online key they still need. Returns the roles signed.
pub async fn sign_online(
    config: &Config,
    base: &Repo,
    repo: &mut Repo,
    roles: &[String],
) -> Result<Vec<String>> {
    let keys = config.keys_by_id()?;
    let mut signers: HashMap<&str, Box<dyn Signer>> = HashMap::new();
    let mut signed = vec![];
    for role in roles {
        for key in repo.missing_keys(base, role)? {
            let Some(uri) = keys
                .get(key.key_id())
                .and_then(|(_, k)| k.online.as_deref())
            else {
                continue;
            };
            if !signers.contains_key(uri) {
                signers.insert(uri, open_signer(uri).await?);
            }
            repo.sign(role, signers[uri].as_ref()).await?;
            signed.push(role.clone());
        }
    }
    Ok(signed)
}

/// Starts and signs new versions of the online roles in the working tree at `dir` that are due.
/// `previous` is the config the current metadata was built from. Returns the roles changed.
pub async fn update_online(
    config: &Config,
    previous: Option<&Config>,
    dir: &std::path::Path,
) -> Result<Vec<String>> {
    let mut repo = Repo::load(dir)?;
    let base = repo.clone();
    let changed = repo.update_online(config, previous, chrono::Utc::now())?;
    sign_online(config, &base, &mut repo, &changed).await?;
    repo.save(dir)?;
    Ok(changed)
}
