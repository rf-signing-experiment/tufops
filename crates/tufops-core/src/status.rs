//! What a signing event changes, and who still has to sign it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

use anyhow::Result;
use chrono::{DateTime, Utc};
use tuf::crypto::{KeyId, PublicKey};
use tuf::metadata::{
    Delegation, MetadataThreshold, MetadataVersion, RootMetadata, TargetDescription, TargetPath,
    TargetsMetadata,
};

use crate::config::{Config, TOP_LEVEL_ROLES};
use crate::publish::{target_object, target_sha256};
use crate::repo::{METADATA, Repo, root_role_keys};

/// A key that signs a role, as the config names it.
#[derive(Clone, Debug)]
pub struct Key {
    pub id: KeyId,
    /// The owner of an offline key, or the name of an online key.
    pub name: String,
    pub online: bool,
}

/// A threshold of signatures a role must reach.
#[derive(Debug)]
pub struct Requirement {
    /// Whether these are the previous root's keys, which must also sign a new root version.
    pub previous_root: bool,
    pub threshold: MetadataThreshold,
    pub signed: Vec<Key>,
    pub unsigned: Vec<Key>,
}

impl Requirement {
    pub fn met(&self) -> bool {
        self.signed.len() as u32 >= self.threshold.get()
    }

    /// Keys whose signatures are still needed: the unsigned ones, until the threshold is met.
    pub fn awaited(&self) -> &[Key] {
        if self.met() { &[] } else { &self.unsigned }
    }
}

/// A change to a role's signed metadata.
#[derive(Debug)]
pub enum Change {
    /// A target added, changed or removed.
    Target {
        path: String,
        kind: &'static str,
        /// The new file, unless the target was removed.
        file: Option<TargetFile>,
    },
    /// Any other change, in words.
    Other(String),
}

#[derive(Debug)]
pub struct TargetFile {
    pub length: u64,
    pub sha256: String,
    /// Where the file was uploaded, relative to the storage root.
    pub object: String,
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Change::Target { path, kind, file } => {
                write!(f, "target {path} {kind}")?;
                match file {
                    Some(file) => write!(f, " ({} bytes, sha256 {})", file.length, file.sha256),
                    None => Ok(()),
                }
            }
            Change::Other(text) => f.write_str(text),
        }
    }
}

#[derive(Debug)]
pub struct RoleStatus {
    pub role: String,
    /// The version and expiry on main, if the role exists there.
    pub base: Option<(MetadataVersion, DateTime<Utc>)>,
    pub version: MetadataVersion,
    pub expires: DateTime<Utc>,
    /// What the metadata changes compared with main.
    pub changes: Vec<Change>,
    pub requirements: Vec<Requirement>,
}

impl RoleStatus {
    pub fn complete(&self) -> bool {
        self.requirements.iter().all(Requirement::met)
    }

    /// Whether the role still needs a signature from `key`.
    pub fn needs(&self, key: &KeyId) -> bool {
        let mut awaited = self.requirements.iter().flat_map(Requirement::awaited);
        awaited.any(|k| &k.id == key)
    }
}

#[derive(Debug)]
pub struct EventStatus {
    /// Roles that changed or lack signatures.
    pub roles: Vec<RoleStatus>,
}

impl EventStatus {
    /// Compares `head` with `base` (the main branch) and checks the signatures in `head`.
    pub fn new(config: &Config, base: &Repo, head: &Repo) -> Result<Self> {
        let (base_index, head_index) = (index_targets(base)?, index_targets(head)?);
        let key = |k: &PublicKey| Key {
            id: k.key_id().clone(),
            name: config.describe_key(k.key_id()),
            online: (config.key_by_id(k.key_id())).is_some_and(|(_, k)| k.online.is_some()),
        };
        let mut roles = vec![];
        for role in &head.event_roles() {
            let changed = base.raw(role) != head.raw(role);
            let mut requirements = vec![];
            for (i, (threshold, role_keys)) in
                head.requirements(base, role)?.into_iter().enumerate()
            {
                let signed = head.signed_by(role, &role_keys)?;
                let (signed, unsigned): (Vec<_>, Vec<_>) =
                    role_keys.iter().partition(|k| signed.contains(k));
                requirements.push(Requirement {
                    previous_root: i > 0,
                    threshold,
                    signed: signed.into_iter().map(key).collect(),
                    unsigned: unsigned.into_iter().map(key).collect(),
                });
            }
            let (version, expires) = head.require_header(role)?;
            let changes = if changed {
                changes(config, (base, &base_index), (head, &head_index), role)?
            } else {
                vec![]
            };
            let status = RoleStatus {
                role: role.to_owned(),
                base: base.header(role)?,
                version,
                expires,
                changes,
                requirements,
            };
            if changed || !status.complete() {
                roles.push(status);
            }
        }
        Ok(Self { roles })
    }

    pub fn complete(&self) -> bool {
        self.roles.iter().all(RoleStatus::complete)
    }

    /// Roles that still need a signature from `key`.
    pub fn needs(&self, key: &KeyId) -> Vec<&RoleStatus> {
        self.roles.iter().filter(|r| r.needs(key)).collect()
    }

    /// Whether CI merges the event by itself: it must be fully signed, signed only by online
    /// keys, and change nothing but metadata. Anything else goes through a pull request.
    pub fn merges_automatically(&self, changed_files: &[String]) -> bool {
        let metadata_only = changed_files
            .iter()
            .all(|f| f.starts_with(&format!("{METADATA}/")));
        self.complete() && !self.offline() && metadata_only
    }

    /// Whether any role in the event is signed with offline keys, so people must review it.
    pub fn offline(&self) -> bool {
        let reqs = self.roles.iter().flat_map(|r| &r.requirements);
        reqs.flat_map(|r| r.signed.iter().chain(&r.unsigned))
            .any(|k| !k.online)
    }

    /// Names of the keys whose signatures are still needed, sorted and without duplicates.
    pub fn waiting_for(&self) -> Vec<&str> {
        let reqs = self.roles.iter().flat_map(|r| &r.requirements);
        let awaited = reqs.flat_map(Requirement::awaited);
        let names: BTreeSet<_> = awaited.map(|k| k.name.as_str()).collect();
        names.into_iter().collect()
    }

    /// What happens next to the event, in words. `changed_files` are as for
    /// `merges_automatically`.
    pub fn next_step(&self, changed_files: &[String]) -> String {
        if !self.complete() {
            let waiting = self.waiting_for().join(", ");
            format!("Waiting for signatures from {waiting}, who can add them with `tufops sign`.")
        } else if self.merges_automatically(changed_files) {
            "All signatures are in: the event merges automatically.".to_owned()
        } else {
            "All signatures are in: a maintainer can now review and merge its pull request."
                .to_owned()
        }
    }
}

/// The start of a key id, enough to tell keys apart.
pub fn short(id: &KeyId) -> &str {
    id.as_str().get(..8).unwrap_or(id.as_str())
}

/// Key names, comma separated, or `-` if there are none.
pub fn names(keys: &[Key]) -> String {
    let names: Vec<_> = keys.iter().map(|k| k.name.as_str()).collect();
    if names.is_empty() {
        "-".to_owned()
    } else {
        names.join(", ")
    }
}

/// Every role listing each target path, with the description it gives.
type TargetIndex = HashMap<TargetPath, Vec<(String, TargetDescription)>>;

fn index_targets(repo: &Repo) -> Result<TargetIndex> {
    let mut index = TargetIndex::new();
    for role in repo.targets_roles() {
        let targets = repo.require::<TargetsMetadata>(&role)?;
        for (path, desc) in targets.targets() {
            index
                .entry(path.clone())
                .or_default()
                .push((role.clone(), desc.clone()));
        }
    }
    Ok(index)
}

/// Describes how `role` in `head` differs from `base`, from the metadata that gets signed.
fn changes(
    config: &Config,
    (base, base_index): (&Repo, &TargetIndex),
    (head, head_index): (&Repo, &TargetIndex),
    role: &str,
) -> Result<Vec<Change>> {
    let mut out = vec![];
    if role == "root" {
        let (new, old) = (head.root()?, base.metadata::<RootMetadata>(role)?);
        for top in TOP_LEVEL_ROLES {
            let what = format!("{top} role");
            let old = old.as_ref().map(|o| root_role_keys(o, top));
            key_changes(&mut out, config, &what, old, root_role_keys(&new, top));
        }
        return Ok(out);
    }

    let new = head.require::<TargetsMetadata>(role)?;
    let old = base.metadata::<TargetsMetadata>(role)?;
    let by_name = |t: &TargetsMetadata| -> BTreeMap<String, _> {
        let roles = t.delegations().roles().iter();
        roles.map(|d| (d.name().to_string(), d.clone())).collect()
    };
    let paths_of =
        |d: &Delegation| -> BTreeSet<_> { d.paths().iter().map(|p| p.to_string()).collect() };
    let (old_d, new_d) = (old.as_ref().map(by_name).unwrap_or_default(), by_name(&new));
    for name in old_d.keys().chain(new_d.keys()).collect::<BTreeSet<_>>() {
        let what = format!("delegation {name}");
        let (old, Some(d)) = (old_d.get(name), new_d.get(name)) else {
            out.push(Change::Other(format!("{what} removed")));
            continue;
        };
        if old.is_none() {
            out.push(Change::Other(format!("{what} added")));
        }
        let old_paths = old.map(paths_of).unwrap_or_default();
        set_changes(&mut out, &format!("{what}: path"), old_paths, paths_of(d));
        let old = old.map(|o| (o.threshold(), o.key_ids()));
        key_changes(&mut out, config, &what, old, (d.threshold(), d.key_ids()));
    }
    // Clients search delegations in order, so reordering them can change which role is trusted
    // for a target.
    if let Some(old) = &old {
        let order = |targets: &TargetsMetadata, other: &BTreeMap<String, Delegation>| {
            let names = targets.delegations().roles().iter();
            let names = names.map(|delegation| delegation.name().to_string());
            names
                .filter(|name| other.contains_key(name))
                .collect::<Vec<_>>()
        };
        let (old_order, new_order) = (order(old, &new_d), order(&new, &old_d));
        if old_order != new_order {
            let (old_order, new_order) = (old_order.join(", "), new_order.join(", "));
            out.push(Change::Other(format!(
                "delegation order: {old_order} → {new_order}"
            )));
        }
    }

    let empty = HashMap::new();
    let old_targets = old.as_ref().map_or(&empty, |o| o.targets());
    let file = |path: &TargetPath, d: &TargetDescription| -> Result<_> {
        Ok(Some(TargetFile {
            length: d.length(),
            sha256: target_sha256(d)?.to_string(),
            object: target_object(path, d)?,
        }))
    };
    // Another role listing the same file: where it moved from, or to, unchanged.
    let other = |index: &TargetIndex, path: &TargetPath, d: &TargetDescription| {
        let holders = index.get(path)?;
        let found = holders.iter().find(|(r, desc)| r != role && desc == d);
        found.map(|(r, _)| r.clone())
    };
    // How many targets moved unchanged, by where from or to.
    let mut moved = BTreeMap::<String, usize>::new();
    let mut count = |how| *moved.entry(how).or_default() += 1;
    let paths: BTreeSet<_> = old_targets.keys().chain(new.targets().keys()).collect();
    for path in paths {
        let (kind, file) = match (old_targets.get(path), new.targets().get(path)) {
            (None, Some(d)) => match other(base_index, path, d) {
                Some(from) => {
                    count(format!("moved here unchanged from {from}"));
                    continue;
                }
                None => ("added", file(path, d)?),
            },
            (Some(d), None) => match other(head_index, path, d) {
                Some(to) => {
                    count(format!("moved unchanged to {to}"));
                    continue;
                }
                None => ("removed", None),
            },
            (Some(a), Some(b)) if a != b => ("changed", file(path, b)?),
            _ => continue,
        };
        out.push(Change::Target {
            path: path.to_string(),
            kind,
            file,
        });
    }
    for (how, n) in moved {
        let s = if n == 1 { "" } else { "s" };
        out.push(Change::Other(format!("{n} target{s} {how}")));
    }
    Ok(out)
}

/// Describes the keys and threshold of a role changing from `old` to `new`.
fn key_changes(
    out: &mut Vec<Change>,
    config: &Config,
    what: &str,
    old: Option<(MetadataThreshold, &HashSet<KeyId>)>,
    (threshold, ids): (MetadataThreshold, &HashSet<KeyId>),
) {
    let describe = |ids: &HashSet<KeyId>| -> BTreeSet<_> {
        let name = |id| format!("{} [{}]", config.describe_key(id), short(id));
        ids.iter().map(name).collect()
    };
    let old_keys = old.map(|(_, ids)| describe(ids)).unwrap_or_default();
    set_changes(out, &format!("{what}: key"), old_keys, describe(ids));
    let threshold = match old {
        None => threshold.to_string(),
        Some((old, _)) if old != threshold => format!("{old} → {threshold}"),
        Some(_) => return,
    };
    out.push(Change::Other(format!("{what}: threshold {threshold}")));
}

/// Describes the items in `new` but not `old` as added, then those in `old` but not `new` as
/// removed.
fn set_changes(out: &mut Vec<Change>, what: &str, old: BTreeSet<String>, new: BTreeSet<String>) {
    let added = new.difference(&old).map(|i| format!("{what} {i} added"));
    let removed = old.difference(&new).map(|i| format!("{what} {i} removed"));
    out.extend(added.chain(removed).map(Change::Other));
}
