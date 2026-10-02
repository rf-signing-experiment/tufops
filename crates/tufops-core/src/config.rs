//! `tufops.toml`: the declarative description of keys and roles.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use tuf::crypto::{KeyId, PublicKey};
use tuf::metadata::{MetadataPath, TargetPath};

use crate::backend::public_key_from_pem;
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
    /// Top-level roles, plus roles delegated from `targets` (those with `paths`).
    pub roles: BTreeMap<String, RoleConfig>,
    /// Delegated roles in the order clients search them in. See `search_order`.
    #[serde(skip)]
    delegation_order: Vec<String>,
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
        let mut config: Config = toml::from_str(text)?;
        config.validate()?;
        config.delegation_order = config.search_order()?;
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
                TargetPath::new(path).with_context(|| format!("role {name}: path"))?;
            }
        }
        Ok(())
    }

    /// Orders the delegated roles the way clients search them: deepest paths first, so that
    /// `fw/beta/` comes before `fw/`, then by name. A role's depth is that of its shallowest path.
    /// Rejected if a role still comes before one with a path its own paths cover, since clients
    /// would never look for that path's targets in the later role.
    fn search_order(&self) -> Result<Vec<String>> {
        let depth = |path: &String| path.split('/').filter(|part| !part.is_empty()).count();
        let mut roles: Vec<_> = (self.roles.iter())
            .filter(|(_, role)| !role.paths.is_empty())
            .collect();
        roles.sort_by_key(|(_, role)| Reverse(role.paths.iter().map(depth).min()));
        // The first role listing each path, and its position.
        let mut first = HashMap::new();
        for (position, (name, role)) in roles.iter().enumerate() {
            for path in &role.paths {
                first.entry(path.as_str()).or_insert((position, name));
            }
        }
        for (position, (name, role)) in roles.iter().enumerate() {
            for path in &role.paths {
                // The paths covering `path`, the way clients match them: `path`, and each
                // directory above it.
                let dirs = path.match_indices('/').map(|(end, _)| &path[..=end]);
                for covering in dirs.chain([path.as_str()]) {
                    if let Some((first_position, first_name)) = first.get(covering) {
                        ensure!(
                            *first_position >= position,
                            "roles {first_name} ({covering}) and {name} ({path}) overlap: \
                             clients would look for {path} in {first_name} only"
                        );
                    }
                }
            }
        }
        Ok(roles.into_iter().map(|(name, _)| name.clone()).collect())
    }

    pub fn role(&self, name: &str) -> Result<&RoleConfig> {
        self.roles
            .get(name)
            .with_context(|| format!("role {name} is not in {FILE}"))
    }

    /// Roles delegated from `targets`, in the order clients search them in.
    pub fn delegations(&self) -> impl Iterator<Item = (&String, &RoleConfig)> {
        (self.delegation_order.iter()).map(|name| (name, &self.roles[name]))
    }

    /// Whether every key of `role` is online.
    pub fn online_only(&self, role: &str) -> bool {
        let online = |k: &String| self.keys.get(k).is_some_and(|k| k.online.is_some());
        self.roles
            .get(role)
            .is_some_and(|r| r.keys.iter().all(online))
    }

    /// Whether CI signs `role` by itself. CI holds only the keys that sign snapshot and
    /// timestamp, so other online keys can be kept from it.
    pub fn ci_signs(&self, role: &str) -> bool {
        let keys = |r: &str| self.roles.get(r).map(|r| r.keys.as_slice());
        let ci = [keys("snapshot"), keys("timestamp")].map(Option::unwrap_or_default);
        keys(role).is_some_and(|keys| keys.iter().all(|k| ci.iter().any(|c| c.contains(k))))
    }

    pub fn public_key(&self, name: &str) -> Result<PublicKey> {
        let key = self
            .keys
            .get(name)
            .with_context(|| format!("unknown key {name}"))?;
        public_key_from_pem(&key.public_key).with_context(|| format!("key {name}: public_key"))
    }

    /// The configured key with id `id`, and its name.
    pub fn key_by_id(&self, id: &KeyId) -> Option<(&String, &KeyConfig)> {
        let has_id = |name: &String| self.public_key(name).is_ok_and(|k| k.key_id() == id);
        self.keys.iter().find(|(name, _)| has_id(name))
    }

    /// A human readable name for a key id: its owner, or its name for online keys.
    pub fn describe_key(&self, id: &KeyId) -> String {
        match self.key_by_id(id) {
            Some((name, key)) => (key.owner.clone()).unwrap_or_else(|| format!("{name} (online)")),
            None => "unknown key".to_owned(),
        }
    }
}
