//! The TUF metadata of a repository: loading, editing and signing it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, SubsecRound, Utc};
use tracing::{debug, warn};
use tuf::crypto::{KeyId, PublicKey, Signature, SignatureValue};
use tuf::metadata::{
    Delegation, Delegations, Metadata, MetadataDescription, MetadataPath, MetadataThreshold,
    MetadataVersion, RawSignedMetadata, RoleDefinition, RootMetadata, SignedMetadataBuilder,
    SnapshotMetadata, TargetDescription, TargetPath, TargetsMetadata, TimestampMetadata,
};
use tuf::pouf::{Pouf, Pouf1};

use crate::backend::Signer;
use crate::config::{Config, RoleConfig, TOP_LEVEL_ROLES};
use crate::git::Git;

/// Directory in the git repository that holds the metadata.
pub const METADATA: &str = "metadata";
/// Every root version, which clients need to walk from the root they trust to the newest.
pub const ROOT_HISTORY: &str = "root_history";

type Build<M> = Box<dyn Fn(MetadataVersion, DateTime<Utc>) -> tuf::Result<M>>;

/// The metadata files of one state of the repository, keyed by path relative to `metadata/`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Repo {
    files: BTreeMap<String, Vec<u8>>,
}

fn file(role: &str) -> String {
    format!("{role}.json")
}

fn history_file(version: u32) -> String {
    format!("{ROOT_HISTORY}/{version}.root.json")
}

/// The names and paths of the `.json` files in `dir`; none if `dir` does not exist.
fn json_files(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut files = vec![];
    for entry in std::fs::read_dir(dir).into_iter().flatten() {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str());
        if let Some(name) = name.filter(|n| n.ends_with(".json") && path.is_file()) {
            files.push((name.to_owned(), path.clone()));
        }
    }
    Ok(files)
}

impl Repo {
    /// Loads the metadata in a working tree.
    pub fn load(dir: &Path) -> Result<Self> {
        let base = dir.join(METADATA);
        let mut files = BTreeMap::new();
        for (name, path) in json_files(&base)? {
            files.insert(name, std::fs::read(path)?);
        }
        for (name, path) in json_files(&base.join(ROOT_HISTORY))? {
            files.insert(format!("{ROOT_HISTORY}/{name}"), std::fs::read(path)?);
        }
        Ok(Self { files })
    }

    /// Loads the metadata at a git revision.
    pub fn load_rev(git: &Git, rev: &str) -> Result<Self> {
        let mut files = BTreeMap::new();
        for path in git.ls(rev, METADATA)? {
            let name = path.strip_prefix(&format!("{METADATA}/"));
            if let Some(name) = name.filter(|n| n.ends_with(".json")) {
                files.insert(name.to_owned(), git.show(rev, &path)?.context("vanished")?);
            }
        }
        Ok(Self { files })
    }

    /// Writes the metadata to a working tree, removing roles that no longer exist.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let base = dir.join(METADATA);
        std::fs::create_dir_all(base.join(ROOT_HISTORY))?;
        for (name, path) in json_files(&base)? {
            if !self.files.contains_key(&name) {
                std::fs::remove_file(path)?;
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

    pub fn require_raw(&self, role: &str) -> Result<&[u8]> {
        self.raw(role)
            .with_context(|| format!("{role} metadata is missing"))
    }

    /// Every root version, oldest first.
    pub fn root_history(&self) -> Result<Vec<&[u8]>> {
        let version = self.root()?.version();
        (1..=version.get())
            .map(|v| {
                let name = history_file(v);
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
            let version = parse_unverified::<RootMetadata>(&pretty)?.version();
            self.files
                .insert(history_file(version.get()), pretty.clone());
        }
        self.files.insert(file(role), pretty);
        Ok(())
    }

    /// Parses `role` without checking its signatures.
    pub fn metadata<M: Metadata>(&self, role: &str) -> Result<Option<M>> {
        let parse = |b| parse_unverified(b).with_context(|| format!("parsing {role} metadata"));
        self.raw(role).map(parse).transpose()
    }

    pub fn require<M: Metadata>(&self, role: &str) -> Result<M> {
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

    /// The roles signing events sign: all but snapshot and timestamp, which CI signs on main.
    /// Root comes first, then targets, then the delegated roles.
    pub fn event_roles(&self) -> Vec<String> {
        let mut roles: Vec<_> = self
            .roles()
            .filter(|r| !matches!(*r, "snapshot" | "timestamp"))
            .collect();
        roles.sort_by_key(|r| (*r != "root", *r != "targets", *r));
        roles.into_iter().map(str::to_owned).collect()
    }

    /// Version and expiry of `role`.
    pub fn header(&self, role: &str) -> Result<Option<(MetadataVersion, DateTime<Utc>)>> {
        type Header = Option<(MetadataVersion, DateTime<Utc>)>;
        fn get<M: Metadata>(repo: &Repo, role: &str) -> Result<Header> {
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

    pub fn require_header(&self, role: &str) -> Result<(MetadataVersion, DateTime<Utc>)> {
        self.header(role)?
            .with_context(|| format!("{role} metadata is missing"))
    }

    /// Threshold and keys `role` must be signed with, according to this repository's metadata.
    pub fn role_keys(&self, role: &str) -> Result<(MetadataThreshold, Vec<PublicKey>)> {
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
        let (threshold, ids) = root_role_keys(&root, role);
        Ok((threshold, pick(ids, root.keys())))
    }

    /// The key sets whose thresholds `role` must meet: its own, and for a new root version also
    /// the previous root's.
    pub fn requirements(
        &self,
        base: &Repo,
        role: &str,
    ) -> Result<Vec<(MetadataThreshold, Vec<PublicKey>)>> {
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
        let verifies = |k: &PublicKey, s: &Signature| {
            k.verify(&path, &input, s)
                .inspect_err(|err| warn!(role, key = %k.key_id(), "bad signature: {err}"))
                .is_ok()
        };
        let valid = |k: &PublicKey| {
            sigs.iter()
                .any(|s| s.key_id() == k.key_id() && verifies(k, s))
        };
        Ok(keys.iter().filter(|k| valid(k)).cloned().collect())
    }

    /// Keys whose signatures `role` still needs to reach its thresholds.
    pub fn missing_keys(&self, base: &Repo, role: &str) -> Result<Vec<PublicKey>> {
        let mut missing = vec![];
        for (threshold, keys) in self.requirements(base, role)? {
            let signed = self.signed_by(role, &keys)?;
            if (signed.len() as u32) < threshold.get() {
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
        debug!(role, key = %key.key_id(), "signing");
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

    /// Replaces `role` with an unsigned `build(version, expires)`, expiring `expires_days` from
    /// now, when:
    /// * that differs from the current content,
    /// * the current version is in its signing period,
    /// * `expires_days` differs from `previous`, the config the current metadata was built from,
    /// * or the version in `base` lacks signatures from the keys the role now has.
    ///
    /// The new version is one more than the version in `base`. Returns `role` if it changed.
    fn update<M: Metadata>(
        &mut self,
        base: &Repo,
        role: &str,
        config: &Config,
        previous: Option<&Config>,
        now: DateTime<Utc>,
        build: Build<M>,
    ) -> Result<Option<String>> {
        let config = config.role(role)?;
        let now = now.trunc_subsecs(0);
        if let Some(cur) = self.metadata::<M>(role)? {
            let unchanged = build(cur.version(), *cur.expires())? == cur;
            let previous = previous.and_then(|p| p.roles.get(role));
            let expiry_changed = previous.is_some_and(|p| p.expires_days != config.expires_days);
            let keys_changed = base.header(role)?.is_some_and(|(v, _)| v == cur.version())
                && !self.missing_keys(base, role)?.is_empty();
            let in_signing_period = config.in_signing_period(cur.expires(), now);
            debug!(
                role,
                version = %cur.version(),
                expires = %cur.expires(),
                unchanged,
                expiry_changed,
                keys_changed,
                in_signing_period,
                "checking whether {role} needs a new version"
            );
            if unchanged && !expiry_changed && !keys_changed && !in_signing_period {
                return Ok(None);
            }
        }
        let version = match base.header(role)? {
            Some((v, _)) => v.checked_add(1).context("version overflow")?,
            None => MetadataVersion::ONE,
        };
        let expires = now + Duration::days(config.expires_days);
        debug!(role, %version, %expires, "starting a new version of {role}");
        let metadata = build(version, expires)?;
        let signed = SignedMetadataBuilder::<Pouf1, M>::from_metadata(&metadata)?.build();
        self.put(role, signed.to_raw()?.as_bytes())?;
        Ok(Some(role.to_owned()))
    }

    /// Brings root, targets and the delegated roles in line with `config`, and starts a new
    /// version of any of them in its signing period. `previous` is the config the current
    /// metadata was built from; roles whose `expires_days` differ from it get a new version too.
    ///
    /// Every target moves to the role its path belongs in under the new delegations, so changing
    /// a role's paths, or replacing it with other roles, moves its targets rather than leaving
    /// them where clients no longer look or dropping them. Returns the roles that changed.
    pub fn apply_config(
        &mut self,
        config: &Config,
        previous: Option<&Config>,
        base: &Repo,
        now: DateTime<Utc>,
    ) -> Result<Vec<String>> {
        let mut changed = vec![];
        changed.extend(self.update(base, "root", config, previous, now, root_builder(config)?)?);

        let delegations = config_delegations(config)?;
        let mut targets: HashMap<String, HashMap<TargetPath, TargetDescription>> = HashMap::new();
        for role in self.targets_roles() {
            let listed = self.require::<TargetsMetadata>(&role)?;
            if role != "targets" && !config.roles.contains_key(&role) {
                self.files.remove(&file(&role));
                changed.push(role.clone());
            }
            for (path, desc) in listed.targets() {
                let dest_role = delegated_role(&delegations, path);
                // Should a path somehow be listed twice, the role it belongs in keeps its entry.
                let stays = dest_role == role;
                let dest = targets.entry(dest_role).or_default();
                if stays || !dest.contains_key(path) {
                    dest.insert(path.clone(), desc.clone());
                }
            }
        }

        let map = targets.remove("targets").unwrap_or_default();
        let build = targets_builder(map, delegations);
        changed.extend(self.update(base, "targets", config, previous, now, build)?);
        for (role, _) in config.delegations() {
            let map = targets.remove(role).unwrap_or_default();
            let build = targets_builder(map, Delegations::default());
            changed.extend(self.update(base, role, config, previous, now, build)?);
        }
        Ok(changed)
    }

    /// The role that `path` belongs in: the first delegation whose paths match, else `targets`.
    pub fn role_for_target(&self, path: &TargetPath) -> Result<String> {
        Ok(delegated_role(self.targets()?.delegations(), path))
    }

    /// Every target that `targets` and the roles delegated from it list, with its description.
    /// Should a path somehow be listed twice, the role it belongs in gives the description.
    pub fn listed_targets(&self) -> Result<HashMap<TargetPath, TargetDescription>> {
        let top = self.targets()?;
        let mut listed = HashMap::new();
        for role in self.targets_roles() {
            let targets = self.require::<TargetsMetadata>(&role)?;
            for (path, desc) in targets.targets() {
                if delegated_role(top.delegations(), path) == role || !listed.contains_key(path) {
                    listed.insert(path.clone(), desc.clone());
                }
            }
        }
        Ok(listed)
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
            changed.extend(self.update(base, &role, config, None, now, build)?);
        }
        Ok(changed)
    }

    /// Removes the targets `remove` picks from every role listing them. Returns the roles changed
    /// and how many targets were removed.
    pub fn remove_targets(
        &mut self,
        config: &Config,
        base: &Repo,
        remove: impl Fn(&TargetPath) -> bool,
        now: DateTime<Utc>,
    ) -> Result<(Vec<String>, usize)> {
        let (mut changed, mut removed) = (vec![], 0);
        for role in self.targets_roles() {
            let cur = self.require::<TargetsMetadata>(&role)?;
            let mut map = cur.targets().clone();
            map.retain(|path, _| !remove(path));
            if map.len() == cur.targets().len() {
                continue;
            }
            removed += cur.targets().len() - map.len();
            let build = targets_builder(map, cur.delegations().clone());
            changed.extend(self.update(base, &role, config, None, now, build)?);
        }
        Ok((changed, removed))
    }

    /// Starts new versions of the roles CI signs: targets roles signed only by snapshot's and
    /// timestamp's keys in their signing period, then snapshot and timestamp whenever what they
    /// describe changed or they are in their signing period. Like `apply_config`, a changed
    /// `expires_days` since `previous` also starts a new version. The new versions still need
    /// signing. Returns the roles changed.
    pub fn update_online(
        &mut self,
        config: &Config,
        previous: Option<&Config>,
        now: DateTime<Utc>,
    ) -> Result<Vec<String>> {
        let base = self.clone();
        let mut changed = vec![];
        for role in self.targets_roles() {
            if config.ci_signs(&role) {
                let cur = self.require::<TargetsMetadata>(&role)?;
                let build = targets_builder(cur.targets().clone(), cur.delegations().clone());
                changed.extend(self.update(&base, &role, config, previous, now, build)?);
            }
        }

        let mut meta = HashMap::new();
        for role in self.targets_roles() {
            let (version, _) = self.require_header(&role)?;
            meta.insert(
                MetadataPath::new(role)?,
                MetadataDescription::new(version, None, HashMap::new())?,
            );
        }
        let build = Box::new(move |v, e| SnapshotMetadata::new(v, e, meta.clone(), HashMap::new()));
        changed.extend(self.update(&base, "snapshot", config, previous, now, build)?);

        let (version, _) = self.require_header("snapshot")?;
        let snapshot = MetadataDescription::new(version, None, HashMap::new())?;
        let build =
            Box::new(move |v, e| TimestampMetadata::new(v, e, snapshot.clone(), HashMap::new()));
        changed.extend(self.update(&base, "timestamp", config, previous, now, build)?);
        Ok(changed)
    }

    /// This repository with `roles` as they are in `other`, including root's history when root
    /// is among them.
    pub fn with_roles_from(&self, other: &Repo, roles: &[String]) -> Repo {
        let mut repo = self.clone();
        let taken = |f: &String| {
            roles.iter().any(|r| *f == file(r))
                || roles.contains(&"root".to_owned()) && f.starts_with(ROOT_HISTORY)
        };
        repo.files.retain(|f, _| !taken(f));
        let files = other.files.iter().filter(|(f, _)| taken(f));
        repo.files
            .extend(files.map(|(f, bytes)| (f.clone(), bytes.clone())));
        repo
    }
}

/// Parses signed metadata without checking its signatures.
pub fn parse_unverified<M: Metadata>(bytes: &[u8]) -> tuf::Result<M> {
    let raw = RawSignedMetadata::<Pouf1, M>::new(bytes.to_vec());
    raw.parse_untrusted()?.assume_valid()
}

/// Threshold and key ids that `root` gives the top-level `role`.
pub fn root_role_keys<'a>(
    root: &'a RootMetadata,
    role: &str,
) -> (MetadataThreshold, &'a HashSet<KeyId>) {
    match role {
        "root" => (root.root().threshold(), root.root().key_ids()),
        "targets" => (root.targets().threshold(), root.targets().key_ids()),
        "snapshot" => (root.snapshot().threshold(), root.snapshot().key_ids()),
        _ => (root.timestamp().threshold(), root.timestamp().key_ids()),
    }
}

/// Whether `pattern` is `path`, or ends in `/` and `path` is under it. Clients use this rule.
pub fn covers(pattern: &TargetPath, path: &TargetPath) -> bool {
    path == pattern || path.is_child(pattern)
}

/// The role `path` belongs in under `delegations`: the first whose paths match, the way clients
/// search them, else `targets`.
fn delegated_role(delegations: &Delegations, path: &TargetPath) -> String {
    let mut roles = delegations.roles().iter();
    let found = roles.find(|d| d.paths().iter().any(|p| covers(p, path)));
    found.map_or("targets", |d| d.name().as_str()).to_owned()
}

/// Adds the keys of `role` to `keys`, returning the role's threshold and key ids.
fn config_role_keys(
    config: &Config,
    role: &RoleConfig,
    keys: &mut HashMap<KeyId, PublicKey>,
) -> Result<(MetadataThreshold, HashSet<KeyId>)> {
    let mut ids = HashSet::new();
    for name in &role.keys {
        let key = config.public_key(name)?;
        ids.insert(key.key_id().clone());
        keys.insert(key.key_id().clone(), key);
    }
    let threshold = NonZeroU32::new(role.threshold).context("threshold must not be 0")?;
    Ok((threshold.into(), ids))
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
