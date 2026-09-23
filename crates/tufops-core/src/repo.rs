//! The TUF metadata of a repository: loading, editing and signing it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, SubsecRound, Utc};
use tuf::crypto::{KeyId, PublicKey, Signature, SignatureValue};
use tuf::metadata::{
    Delegation, Delegations, Metadata, MetadataDescription, MetadataPath, RawSignedMetadata,
    RoleDefinition, RootMetadata, SignedMetadataBuilder, SnapshotMetadata, TargetDescription,
    TargetPath, TargetsMetadata, TimestampMetadata,
};
use tuf::pouf::{Pouf, Pouf1};

use crate::backend::Signer;
use crate::config::{Config, RoleConfig, TOP_LEVEL_ROLES};
use crate::git::Git;

/// Directory in the git repository that holds the metadata.
pub const METADATA: &str = "metadata";
/// Every root version, which clients need to walk from the root they trust to the newest.
pub const ROOT_HISTORY: &str = "root_history";

type Build<M> = Box<dyn Fn(u32, DateTime<Utc>) -> tuf::Result<M>>;

/// The metadata files of one state of the repository, keyed by path relative to `metadata/`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Repo {
    files: BTreeMap<String, Vec<u8>>,
}

fn file(role: &str) -> String {
    format!("{role}.json")
}

impl Repo {
    /// Loads the metadata in a working tree.
    pub fn load(dir: &Path) -> Result<Self> {
        let mut files = BTreeMap::new();
        let base = dir.join(METADATA);
        for (prefix, sub) in [
            ("", base.clone()),
            ("root_history/", base.join(ROOT_HISTORY)),
        ] {
            let Ok(entries) = std::fs::read_dir(&sub) else {
                continue;
            };
            for entry in entries {
                let path = entry?.path();
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .context("bad file name")?;
                if path.is_file() && name.ends_with(".json") {
                    files.insert(format!("{prefix}{name}"), std::fs::read(&path)?);
                }
            }
        }
        Ok(Self { files })
    }

    /// Loads the metadata at a git revision.
    pub fn load_rev(git: &Git, rev: &str) -> Result<Self> {
        let mut files = BTreeMap::new();
        for path in git.ls(rev, METADATA)? {
            if let Some(name) = path
                .strip_prefix("metadata/")
                .filter(|n| n.ends_with(".json"))
            {
                files.insert(name.to_owned(), git.show(rev, &path)?.context("vanished")?);
            }
        }
        Ok(Self { files })
    }

    /// Writes the metadata to a working tree, removing roles that no longer exist.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let base = dir.join(METADATA);
        std::fs::create_dir_all(base.join(ROOT_HISTORY))?;
        for entry in std::fs::read_dir(&base)? {
            let path = entry?.path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if path.is_file() && name.ends_with(".json") && !self.files.contains_key(name) {
                std::fs::remove_file(&path)?;
            }
        }
        for (name, bytes) in &self.files {
            std::fs::write(base.join(name), bytes)?;
        }
        Ok(())
    }

    pub fn raw(&self, role: &str) -> Option<&[u8]> {
        self.files.get(&file(role)).map(Vec::as_slice)
    }

    fn require_raw(&self, role: &str) -> Result<&[u8]> {
        self.raw(role)
            .with_context(|| format!("{role} metadata is missing"))
    }

    /// Every root version, oldest first.
    pub fn root_history(&self) -> Result<Vec<&[u8]>> {
        let version = self.root()?.version();
        (1..=version)
            .map(|v| {
                let name = format!("{ROOT_HISTORY}/{v}.root.json");
                self.files
                    .get(&name)
                    .map(Vec::as_slice)
                    .with_context(|| format!("missing {name}"))
            })
            .collect()
    }

    fn put(&mut self, role: &str, bytes: &[u8]) -> Result<()> {
        // Store pretty JSON for readable diffs; signatures only cover the canonical form.
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        let mut pretty = serde_json::to_vec_pretty(&value)?;
        pretty.push(b'\n');
        if role == "root" {
            let raw = RawSignedMetadata::<Pouf1, RootMetadata>::new(pretty.clone());
            let version = raw.parse_untrusted()?.assume_valid()?.version();
            self.files.insert(
                format!("{ROOT_HISTORY}/{version}.root.json"),
                pretty.clone(),
            );
        }
        self.files.insert(file(role), pretty);
        Ok(())
    }

    /// Parses `role` without checking its signatures.
    pub fn metadata<M: Metadata>(&self, role: &str) -> Result<Option<M>> {
        let Some(bytes) = self.raw(role) else {
            return Ok(None);
        };
        let raw = RawSignedMetadata::<Pouf1, M>::new(bytes.to_vec());
        let parsed = raw.parse_untrusted().and_then(|s| s.assume_valid());
        Ok(Some(
            parsed.with_context(|| format!("parsing {role} metadata"))?,
        ))
    }

    fn require<M: Metadata>(&self, role: &str) -> Result<M> {
        self.metadata(role)?
            .with_context(|| format!("{role} metadata is missing"))
    }

    pub fn root(&self) -> Result<RootMetadata> {
        self.require("root")
    }

    pub fn targets(&self) -> Result<TargetsMetadata> {
        self.require("targets")
    }

    /// Names of all roles present.
    pub fn roles(&self) -> impl Iterator<Item = &str> {
        self.files
            .keys()
            .filter_map(|f| f.strip_suffix(".json"))
            .filter(|r| !r.contains('/'))
    }

    /// `targets` and the roles delegated from it.
    pub fn targets_roles(&self) -> Vec<String> {
        let top = |r: &str| TOP_LEVEL_ROLES.contains(&r) && r != "targets";
        self.roles()
            .filter(|r| !top(r))
            .map(str::to_owned)
            .collect()
    }

    /// Version and expiry of `role`.
    pub fn header(&self, role: &str) -> Result<Option<(u32, DateTime<Utc>)>> {
        fn get<M: Metadata>(repo: &Repo, role: &str) -> Result<Option<(u32, DateTime<Utc>)>> {
            Ok(repo
                .metadata::<M>(role)?
                .map(|m| (m.version(), *m.expires())))
        }
        match role {
            "root" => get::<RootMetadata>(self, role),
            "snapshot" => get::<SnapshotMetadata>(self, role),
            "timestamp" => get::<TimestampMetadata>(self, role),
            _ => get::<TargetsMetadata>(self, role),
        }
    }

    /// Threshold and keys `role` must be signed with, according to this repository's metadata.
    pub fn role_keys(&self, role: &str) -> Result<(u32, Vec<PublicKey>)> {
        let pick = |ids: &HashSet<KeyId>, keys: &HashMap<KeyId, PublicKey>| {
            let mut picked: Vec<_> = ids.iter().filter_map(|id| keys.get(id).cloned()).collect();
            picked.sort();
            picked
        };
        if !TOP_LEVEL_ROLES.contains(&role) {
            let targets = self.targets()?;
            let d = targets
                .delegations()
                .roles()
                .iter()
                .find(|d| d.name().as_str() == role);
            let d = d.with_context(|| format!("targets does not delegate to {role}"))?;
            return Ok((
                d.threshold(),
                pick(d.key_ids(), targets.delegations().keys()),
            ));
        }
        let root = self.root()?;
        let (threshold, ids) = match role {
            "root" => (root.root().threshold(), root.root().key_ids()),
            "targets" => (root.targets().threshold(), root.targets().key_ids()),
            "snapshot" => (root.snapshot().threshold(), root.snapshot().key_ids()),
            _ => (root.timestamp().threshold(), root.timestamp().key_ids()),
        };
        Ok((threshold, pick(ids, root.keys())))
    }

    /// The key sets whose thresholds `role` must meet: its own, and for a new root version also
    /// the previous root's.
    pub fn requirements(&self, base: &Repo, role: &str) -> Result<Vec<(u32, Vec<PublicKey>)>> {
        let mut reqs = vec![self.role_keys(role)?];
        if role == "root"
            && base
                .raw("root")
                .is_some_and(|b| Some(b) != self.raw("root"))
        {
            reqs.push(base.role_keys("root")?);
        }
        Ok(reqs)
    }

    /// Keys among `keys` with a valid signature on `role`.
    pub fn signed_by(&self, role: &str, keys: &[PublicKey]) -> Result<Vec<PublicKey>> {
        let (sigs, raw) = Pouf1::deserialize_signed(self.require_raw(role)?)?;
        let input = Pouf1::signing_input(&raw)?;
        let path = MetadataPath::new(role.to_owned())?;
        let valid = |k: &PublicKey| {
            sigs.iter()
                .any(|s| s.key_id() == k.key_id() && k.verify(&path, &input, s).is_ok())
        };
        Ok(keys.iter().filter(|k| valid(k)).cloned().collect())
    }

    /// Keys whose signatures `role` still needs to reach its thresholds.
    pub fn missing_keys(&self, base: &Repo, role: &str) -> Result<Vec<PublicKey>> {
        let mut missing = vec![];
        for (threshold, keys) in self.requirements(base, role)? {
            let signed = self.signed_by(role, &keys)?;
            if (signed.len() as u32) < threshold {
                missing.extend(keys.into_iter().filter(|k| !signed.contains(k)));
            }
        }
        Ok(missing)
    }

    /// Adds `signer`'s signature to `role`, replacing any earlier one from the same key.
    pub async fn sign(&mut self, role: &str, signer: &dyn Signer) -> Result<()> {
        let (mut sigs, raw) = Pouf1::deserialize_signed(self.require_raw(role)?)?;
        let input = Pouf1::signing_input(&raw)?;
        let key = signer.public_key();
        let sig = Signature::new(
            key.key_id().clone(),
            SignatureValue::new(signer.sign(&input).await?),
        );
        key.verify(&MetadataPath::new(role.to_owned())?, &input, &sig)
            .context("the new signature does not verify")?;
        sigs.retain(|s| s.key_id() != key.key_id());
        sigs.push(sig);
        sigs.sort();
        self.put(role, &Pouf1::serialize_signed(&sigs, &raw)?)
    }

    /// Replaces `role` with an unsigned `build(version, expires)` when that differs from the
    /// current content, when the current version is in its signing period, or when the version in
    /// `base` lacks signatures from the keys the role now has. The new version is one more than
    /// the version in `base`. Returns whether the role changed.
    fn update<M: Metadata>(
        &mut self,
        base: &Repo,
        role: &str,
        config: &RoleConfig,
        now: DateTime<Utc>,
        build: Build<M>,
    ) -> Result<bool> {
        let now = now.trunc_subsecs(0);
        if let Some(cur) = self.metadata::<M>(role)? {
            let unchanged = build(cur.version(), *cur.expires())? == cur;
            let keys_changed = base.header(role)?.is_some_and(|(v, _)| v == cur.version())
                && !self.missing_keys(base, role)?.is_empty();
            if unchanged && !keys_changed && !config.in_signing_period(cur.expires(), now) {
                return Ok(false);
            }
        }
        let version = base.header(role)?.map_or(1, |(v, _)| v + 1);
        let metadata = build(version, now + Duration::days(config.expires_days))?;
        let signed = SignedMetadataBuilder::<Pouf1, M>::from_metadata(&metadata)?.build();
        self.put(role, signed.to_raw()?.as_bytes())?;
        Ok(true)
    }

    /// Brings root, targets and the delegated roles in line with `config`, and starts a new
    /// version of any of them in its signing period. Returns the roles that changed.
    pub fn apply_config(
        &mut self,
        config: &Config,
        base: &Repo,
        now: DateTime<Utc>,
    ) -> Result<Vec<String>> {
        let mut changed = vec![];
        if self.update(
            base,
            "root",
            config.role("root")?,
            now,
            root_builder(config)?,
        )? {
            changed.push("root".to_owned());
        }
        let targets = self.metadata::<TargetsMetadata>("targets")?;
        let build = targets_builder(
            targets.map(|t| t.targets().clone()).unwrap_or_default(),
            config_delegations(config)?,
        );
        if self.update(base, "targets", config.role("targets")?, now, build)? {
            changed.push("targets".to_owned());
        }
        for role in self.targets_roles() {
            if role != "targets" && !config.roles.contains_key(&role) {
                self.files.remove(&file(&role));
                changed.push(role);
            }
        }
        for (role, role_config) in config.delegations() {
            let targets = self.metadata::<TargetsMetadata>(role)?;
            let map = targets.map(|t| t.targets().clone()).unwrap_or_default();
            if self.update(
                base,
                role,
                role_config,
                now,
                targets_builder(map, Delegations::default()),
            )? {
                changed.push(role.clone());
            }
        }
        Ok(changed)
    }

    /// The role that `path` belongs in: the first delegation whose paths match, else `targets`.
    pub fn role_for_target(&self, path: &TargetPath) -> Result<String> {
        let targets = self.targets()?;
        let found = targets
            .delegations()
            .roles()
            .iter()
            .find(|d| path.matches_chain(&[d.paths().clone()]));
        Ok(found.map_or("targets", |d| d.name().as_str()).to_owned())
    }

    /// Adds or replaces targets, in the roles their paths belong in. Returns the roles changed.
    pub fn add_targets(
        &mut self,
        config: &Config,
        base: &Repo,
        targets: Vec<(TargetPath, TargetDescription)>,
        now: DateTime<Utc>,
    ) -> Result<Vec<String>> {
        let mut by_role: BTreeMap<String, Vec<_>> = BTreeMap::new();
        for (path, desc) in targets {
            by_role
                .entry(self.role_for_target(&path)?)
                .or_default()
                .push((path, desc));
        }
        let mut changed = vec![];
        for (role, new) in by_role {
            let cur = self.require::<TargetsMetadata>(&role)?;
            let mut map = cur.targets().clone();
            map.extend(new);
            let build = targets_builder(map, cur.delegations().clone());
            if self.update(base, &role, config.role(&role)?, now, build)? {
                changed.push(role);
            }
        }
        Ok(changed)
    }

    /// Starts new versions of the roles only online keys sign: online targets roles in their
    /// signing period, then snapshot and timestamp whenever what they describe changed or they
    /// are in their signing period. The new versions still need signing. Returns the roles
    /// changed.
    pub fn update_online(&mut self, config: &Config, now: DateTime<Utc>) -> Result<Vec<String>> {
        let base = self.clone();
        let mut changed = vec![];
        for role in self.targets_roles() {
            let role_config = config.role(&role)?;
            if role_config
                .keys
                .iter()
                .all(|k| config.keys[k].online.is_some())
            {
                let cur = self.require::<TargetsMetadata>(&role)?;
                let build = targets_builder(cur.targets().clone(), cur.delegations().clone());
                if self.update(&base, &role, role_config, now, build)? {
                    changed.push(role);
                }
            }
        }

        let mut meta = HashMap::new();
        for role in self.targets_roles() {
            let (version, _) = self.header(&role)?.context("vanished")?;
            meta.insert(
                MetadataPath::new(role)?,
                MetadataDescription::new(version, None, HashMap::new())?,
            );
        }
        let build = Box::new(move |v, e| SnapshotMetadata::new(v, e, meta.clone(), HashMap::new()));
        if self.update(&base, "snapshot", config.role("snapshot")?, now, build)? {
            changed.push("snapshot".to_owned());
        }

        let (version, _) = self.header("snapshot")?.context("vanished")?;
        let snapshot = MetadataDescription::new(version, None, HashMap::new())?;
        let build =
            Box::new(move |v, e| TimestampMetadata::new(v, e, snapshot.clone(), HashMap::new()));
        if self.update(&base, "timestamp", config.role("timestamp")?, now, build)? {
            changed.push("timestamp".to_owned());
        }
        Ok(changed)
    }
}

/// Adds the keys of `role` to `keys`, returning the role's threshold and key ids.
fn config_role_keys(
    config: &Config,
    role: &RoleConfig,
    keys: &mut HashMap<KeyId, PublicKey>,
) -> Result<(u32, HashSet<KeyId>)> {
    let mut ids = HashSet::new();
    for name in &role.keys {
        let key = config.public_key(name)?;
        ids.insert(key.key_id().clone());
        keys.insert(key.key_id().clone(), key);
    }
    Ok((role.threshold, ids))
}

fn root_builder(config: &Config) -> Result<Build<RootMetadata>> {
    let mut keys = HashMap::new();
    let mut def = |role| config_role_keys(config, config.role(role)?, &mut keys);
    let [root, targets, snapshot, timestamp] = [
        def("root")?,
        def("targets")?,
        def("snapshot")?,
        def("timestamp")?,
    ];
    Ok(Box::new(move |version, expires| {
        RootMetadata::new(
            version,
            expires,
            true,
            keys.clone(),
            RoleDefinition::new(root.0, root.1.clone())?,
            RoleDefinition::new(snapshot.0, snapshot.1.clone())?,
            RoleDefinition::new(targets.0, targets.1.clone())?,
            RoleDefinition::new(timestamp.0, timestamp.1.clone())?,
            HashMap::new(),
        )
    }))
}

fn targets_builder(
    targets: HashMap<TargetPath, TargetDescription>,
    delegations: Delegations,
) -> Build<TargetsMetadata> {
    Box::new(move |version, expires| {
        TargetsMetadata::new(
            version,
            expires,
            targets.clone(),
            delegations.clone(),
            HashMap::new(),
        )
    })
}

fn config_delegations(config: &Config) -> Result<Delegations> {
    let mut keys = HashMap::new();
    let mut roles = vec![];
    for (name, role) in config.delegations() {
        let (threshold, ids) = config_role_keys(config, role, &mut keys)?;
        let paths = role
            .paths
            .iter()
            .map(|p| TargetPath::new(p.clone()))
            .collect::<tuf::Result<_>>()?;
        roles.push(Delegation::new(
            MetadataPath::new(name.clone())?,
            true,
            threshold,
            ids,
            paths,
        )?);
    }
    Ok(Delegations::new(keys, roles)?)
}
