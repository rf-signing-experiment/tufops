//! `tufops.toml`: the declarative description of keys and roles.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use tuf::crypto::{KeyId, KeyType, PublicKey, SignatureScheme};
use tuf::metadata::{MetadataPath, TargetPath};

use crate::git::Git;

pub const FILE: &str = "tufops.toml";

/// Roles every repository has. Any other role is delegated from `targets`.
pub const TOP_LEVEL_ROLES: [&str; 4] = ["root", "targets", "snapshot", "timestamp"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where the repository is published, for example `gs://bucket/prefix`.
    pub storage: String,
    pub keys: BTreeMap<String, KeyConfig>,
    /// Top-level roles, plus roles delegated from `targets` (those with `paths`). Delegations are
    /// kept sorted by name, which is also the order clients search them in.
    pub roles: BTreeMap<String, RoleConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// GitHub user (`@name`) who holds this key on a YubiKey.
    pub owner: Option<String>,
    /// Cloud KMS URI of an online key.
    pub online: Option<String>,
    /// PEM encoded ECDSA P-256 public key.
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleConfig {
    pub keys: Vec<String>,
    pub threshold: u32,
    /// How long a new version of the role is valid for.
    pub expires_days: i64,
    /// How long before expiry a new version is signed.
    pub signing_days: i64,
    /// Target paths delegated to this role; only for roles delegated from `targets`.
    #[serde(default)]
    pub paths: Vec<String>,
}

impl RoleConfig {
    pub fn in_signing_period(&self, expires: &DateTime<Utc>, now: DateTime<Utc>) -> bool {
        *expires - now < Duration::days(self.signing_days)
    }
}

impl Config {
    pub fn load(repo_dir: &Path) -> Result<Self> {
        let path = repo_dir.join(FILE);
        let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path:?}"))?;
        Self::parse(&text).with_context(|| format!("invalid {path:?}"))
    }

    /// Loads the config at a git revision.
    pub fn load_rev(git: &Git, rev: &str) -> Result<Self> {
        let bytes = git
            .show(rev, FILE)?
            .with_context(|| format!("no {FILE} at {rev}"))?;
        Self::parse(std::str::from_utf8(&bytes)?)
            .with_context(|| format!("invalid {FILE} at {rev}"))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        for (name, key) in &self.keys {
            ensure!(
                key.owner.is_some() != key.online.is_some(),
                "key {name}: set exactly one of `owner` or `online`"
            );
            self.public_key(name)?;
        }
        for top in TOP_LEVEL_ROLES {
            ensure!(self.roles.contains_key(top), "missing role {top}");
        }
        for (name, role) in &self.roles {
            MetadataPath::new(name.clone()).with_context(|| format!("role name {name}"))?;
            ensure!(
                role.threshold >= 1 && role.threshold as usize <= role.keys.len(),
                "role {name}: threshold must be between 1 and the number of keys"
            );
            ensure!(
                0 < role.signing_days && role.signing_days < role.expires_days,
                "role {name}: need 0 < signing_days < expires_days"
            );
            for key in &role.keys {
                let Some(k) = self.keys.get(key) else {
                    bail!("role {name}: unknown key {key}")
                };
                if matches!(name.as_str(), "snapshot" | "timestamp") {
                    ensure!(k.online.is_some(), "role {name}: key {key} must be online");
                }
            }
            let top = TOP_LEVEL_ROLES.contains(&name.as_str());
            ensure!(
                top == role.paths.is_empty(),
                "role {name}: `paths` must be set on delegated roles only"
            );
            for path in &role.paths {
                TargetPath::new(path.clone()).with_context(|| format!("role {name}: path"))?;
            }
        }
        // Clients stop at the first delegation covering a target, and delegations are always in
        // alphabetical order, so each path may belong to one role only.
        let paths: Vec<_> = self
            .delegations()
            .flat_map(|(role, conf)| conf.paths.iter().map(move |path| (role, path)))
            .collect();
        let covers = |dir: &str, path: &str| dir.ends_with('/') && path.starts_with(dir);
        for (i, (a, p)) in paths.iter().enumerate() {
            for (b, q) in &paths[i + 1..] {
                ensure!(
                    a == b || !(p == q || covers(p, q) || covers(q, p)),
                    "roles {a} ({p}) and {b} ({q}) overlap: each path may belong to one role only"
                );
            }
        }
        Ok(())
    }

    pub fn role(&self, name: &str) -> Result<&RoleConfig> {
        self.roles
            .get(name)
            .with_context(|| format!("role {name} is not in {FILE}"))
    }

    /// Roles delegated from `targets`.
    pub fn delegations(&self) -> impl Iterator<Item = (&String, &RoleConfig)> {
        self.roles.iter().filter(|(_, r)| !r.paths.is_empty())
    }

    pub fn public_key(&self, name: &str) -> Result<PublicKey> {
        let key = self
            .keys
            .get(name)
            .with_context(|| format!("unknown key {name}"))?;
        PublicKey::from_pem(
            &key.public_key,
            KeyType::Ecdsa,
            SignatureScheme::EcdsaSha2NistP256,
        )
        .with_context(|| format!("key {name}: public_key"))
    }

    /// Configured keys by key id.
    pub fn keys_by_id(&self) -> Result<HashMap<KeyId, (&str, &KeyConfig)>> {
        self.keys
            .iter()
            .map(|(name, key)| {
                Ok((
                    self.public_key(name)?.key_id().clone(),
                    (name.as_str(), key),
                ))
            })
            .collect()
    }

    /// A human readable name for a key id: its owner, or its name for online keys.
    pub fn describe_key(&self, id: &KeyId) -> String {
        match self
            .keys_by_id()
            .ok()
            .and_then(|keys| keys.get(id).copied())
        {
            Some((
                _,
                KeyConfig {
                    owner: Some(owner), ..
                },
            )) => owner.clone(),
            Some((name, _)) => format!("{name} (online)"),
            None => "unknown key".to_owned(),
        }
    }
}
