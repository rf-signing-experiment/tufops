//! `tufops.toml`: the declarative description of keys and roles.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use tuf::crypto::{KeyId, PublicKey};
use tuf::metadata::{MetadataPath, PathPattern};

use crate::backend::public_key_from_pem;
use crate::git::Git;
use crate::pattern;

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
    /// Patterns of the target paths delegated to this role; only for roles delegated from
    /// `targets`.
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
                PathPattern::new(path).with_context(|| format!("role {name}: path {path}"))?;
                ensure!(
                    !path.ends_with('/'),
                    "role {name}: path {path} matches no target: paths are patterns that match \
                     whole target paths, such as {path}* for the targets directly in {path}"
                );
                ensure!(
                    !path.contains('['),
                    "role {name}: path {path}: `[` is not supported, since clients disagree on \
                     what it matches"
                );
            }
        }
        Ok(())
    }

    /// Orders the delegated roles the way clients search them: those with more specific patterns
    /// first, so that `fw/beta-*` comes before `fw/*`, then by name. A pattern is more specific
    /// the more characters other than wildcards it has, then the more `?` and the fewer `*` it
    /// has, and a role is placed by its least specific pattern. Rejected if patterns of two roles
    /// match some path in common, unless the first role's pattern only matches paths the other's
    /// matches too: otherwise clients would look for some of the later role's targets in the
    /// first.
    fn search_order(&self) -> Result<Vec<String>> {
        let specificity = |path: &String| {
            let count = |wildcard: char| path.matches(wildcard).count();
            let (stars, questions) = (count('*'), count('?'));
            (
                path.chars().count() - stars - questions,
                questions,
                Reverse(stars),
            )
        };
        let mut roles: Vec<_> = (self.roles.iter())
            .filter(|(_, role)| !role.paths.is_empty())
            .collect();
        roles.sort_by_key(|(_, role)| Reverse(role.paths.iter().map(specificity).min()));
        // Every path, with the position of its role.
        let paths: Vec<_> = (roles.iter().enumerate())
            .flat_map(|(position, (name, role))| {
                role.paths.iter().map(move |path| (position, name, path))
            })
            .collect();
        for (index, (position, name, path)) in paths.iter().enumerate() {
            for (later_position, later_name, later_path) in &paths[index + 1..] {
                if position == later_position || !pattern::overlap(path, later_path) {
                    continue;
                }
                ensure!(
                    pattern::contains(later_path, path) && !pattern::contains(path, later_path),
                    "roles {name} ({path}) and {later_name} ({later_path}) overlap, but clients \
                     search {name} first and {path} is not more specific"
                );
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
