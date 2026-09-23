//! What a signing event changes, and who still has to sign it.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use anyhow::Result;
use tuf::crypto::KeyId;
use tuf::metadata::TargetsMetadata;

use crate::config::Config;
use crate::repo::Repo;

#[derive(Debug)]
pub struct RoleStatus {
    pub role: String,
    pub version: u32,
    pub changed: bool,
    /// Whether these are the previous root's keys, which must also sign a new root version.
    pub previous_root: bool,
    pub threshold: u32,
    pub signed: Vec<KeyId>,
    pub unsigned: Vec<KeyId>,
}

impl RoleStatus {
    pub fn complete(&self) -> bool {
        self.signed.len() as u32 >= self.threshold
    }
}

#[derive(Debug)]
pub struct TargetChange {
    pub role: String,
    pub path: String,
    pub change: &'static str,
}

#[derive(Debug)]
pub struct EventStatus {
    /// Roles that changed or lack signatures. A new root version appears twice: once for its
    /// own keys and once for the previous root's.
    pub roles: Vec<RoleStatus>,
    pub targets: Vec<TargetChange>,
}

impl EventStatus {
    /// Compares `head` with `base` (the main branch) and checks the signatures in `head`.
    pub fn new(base: &Repo, head: &Repo) -> Result<Self> {
        let mut roles = vec![];
        for role in head
            .roles()
            .filter(|r| !matches!(*r, "snapshot" | "timestamp"))
        {
            let changed = base.raw(role) != head.raw(role);
            let (version, _) = head.header(role)?.unwrap_or_default();
            for (i, (threshold, keys)) in head.requirements(base, role)?.into_iter().enumerate() {
                let signed = head.signed_by(role, &keys)?;
                let status = RoleStatus {
                    role: role.to_owned(),
                    version,
                    changed,
                    previous_root: i > 0,
                    threshold,
                    unsigned: keys
                        .iter()
                        .filter(|k| !signed.contains(k))
                        .map(|k| k.key_id().clone())
                        .collect(),
                    signed: signed.iter().map(|k| k.key_id().clone()).collect(),
                };
                if changed || !status.complete() {
                    roles.push(status);
                }
            }
        }

        let mut targets = vec![];
        let all_roles: BTreeSet<String> = base
            .targets_roles()
            .into_iter()
            .chain(head.targets_roles())
            .collect();
        for role in all_roles {
            let old = base
                .metadata::<TargetsMetadata>(&role)?
                .map(|t| t.targets().clone())
                .unwrap_or_default();
            let new = head
                .metadata::<TargetsMetadata>(&role)?
                .map(|t| t.targets().clone())
                .unwrap_or_default();
            let paths: BTreeSet<_> = old.keys().chain(new.keys()).collect();
            for path in paths {
                let change = match (old.get(path), new.get(path)) {
                    (None, Some(_)) => "added",
                    (Some(_), None) => "removed",
                    (Some(a), Some(b)) if a != b => "modified",
                    _ => continue,
                };
                targets.push(TargetChange {
                    role: role.clone(),
                    path: path.to_string(),
                    change,
                });
            }
        }
        Ok(Self { roles, targets })
    }

    pub fn complete(&self) -> bool {
        self.roles.iter().all(RoleStatus::complete)
    }

    /// Roles that still need a signature from `key`.
    pub fn needs(&self, key: &KeyId) -> BTreeSet<&str> {
        let needed = self
            .roles
            .iter()
            .filter(|r| !r.complete() && r.unsigned.contains(key));
        needed.map(|r| r.role.as_str()).collect()
    }

    pub fn to_markdown(&self, config: &Config) -> String {
        let names = |ids: &[KeyId]| {
            let names: Vec<_> = ids.iter().map(|id| config.describe_key(id)).collect();
            if names.is_empty() {
                "-".to_owned()
            } else {
                names.join(", ")
            }
        };
        let mut out = String::from("| Role | Version | Signatures | Signed by | Not signed by |\n");
        out.push_str("|---|---|---|---|---|\n");
        for r in &self.roles {
            let mark = if r.complete() { "✅" } else { "⏳" };
            let previous = if r.previous_root {
                " (previous keys)"
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "| {}{previous} | {} | {mark} {} of {} | {} | {} |",
                r.role,
                r.version,
                r.signed.len(),
                r.threshold,
                names(&r.signed),
                names(&r.unsigned)
            );
        }
        if !self.targets.is_empty() {
            out.push_str("\n| Target | Role | Change |\n|---|---|---|\n");
            for t in &self.targets {
                let _ = writeln!(out, "| `{}` | {} | {} |", t.path, t.role, t.change);
            }
        }
        out
    }
}
