//! The signing status as markdown for pull requests. `tufops` renders the same status as plain
//! text for the terminal in `ui.rs`, with matching functions: change the two together.

use std::fmt::Write as _;

use chrono::{DateTime, Utc};
use tufops_core::EventStatus;
use tufops_core::backend::BlobStore;
use tufops_core::status::{Change, Requirement, RoleStatus, names};

/// How long the list of changes may grow. GitHub rejects descriptions over 65536 characters, so
/// this leaves room for the rest.
const LIMIT: usize = 30_000;

const TABLE_HEAD: &str = "| Role | Version | Expires | Signatures | Signed by | Waiting for |\n\
                          |---|---|---|---|---|---|";

/// Writes what a signing event changes and who has signed it: a table of requirements, then
/// each role's changes, with target files linked to their uploads in `store`.
pub fn write_event(out: &mut String, branch: &str, status: &EventStatus, store: &dyn BlobStore) {
    let _ = writeln!(out, "## Signing event `{branch}`\n\n{TABLE_HEAD}");
    for role in &status.roles {
        role.requirements
            .iter()
            .for_each(|req| write_requirement(out, role, req));
    }
    let left_out: usize = status.roles.iter().map(|r| write_role(out, r, store)).sum();
    if left_out > 0 {
        let _ = writeln!(
            out,
            "\n…and {left_out} more changes: run `tufops status` for the full list."
        );
    }
}

/// Writes a role's changes until `out` is longer than `LIMIT`. Returns how many it left out.
fn write_role(out: &mut String, role: &RoleStatus, store: &dyn BlobStore) -> usize {
    if role.changes.is_empty() || out.len() > LIMIT {
        return role.changes.len();
    }
    let _ = writeln!(out, "\n**Changes to {}**\n", role.role);
    for (i, change) in role.changes.iter().enumerate() {
        if out.len() > LIMIT {
            return role.changes.len() - i;
        }
        write_change(out, change, store);
    }
    0
}

/// Writes a change as a list item, linking a target's file to its upload in `store`. The terminal
/// prints changes with their `Display` instead.
fn write_change(out: &mut String, change: &Change, store: &dyn BlobStore) {
    let _ = match change {
        Change::Target { path, kind, file } => match file {
            Some(file) => writeln!(
                out,
                "- target [`{path}`](<{}>) {kind} ({} bytes, sha256 `{}`)",
                store.public_url(&file.object),
                file.length,
                file.sha256
            ),
            None => writeln!(out, "- target `{path}` {kind}"),
        },
        Change::Other(text) => writeln!(out, "- {text}"),
    };
}

/// Writes a table row: whether a requirement of `role` is met, who signed it, and who it still
/// waits for.
fn write_requirement(out: &mut String, role: &RoleStatus, req: &Requirement) {
    let mark = if req.met() { "✅" } else { "⏳" };
    let label = if req.previous_root {
        " (previous keys)"
    } else {
        ""
    };
    let (version, expires) = version(role);
    let (signed, awaited) = (names(&req.signed), names(req.awaited()));
    let (n, threshold, name) = (req.signed.len(), req.threshold, &role.role);
    let _ = writeln!(
        out,
        "| {name}{label} | {version} | {expires} | {mark} {n} of {threshold} | {signed} | {awaited} |"
    );
}

/// The version and expiry columns: what main has, and what the event changes them to.
fn version(role: &RoleStatus) -> (String, String) {
    let date = |d: &DateTime<Utc>| d.format("%Y-%m-%d").to_string();
    match role.base {
        Some((version, expires)) if version != role.version => (
            format!("{version} → {}", role.version),
            format!("{} → {}", date(&expires), date(&role.expires)),
        ),
        _ => (role.version.to_string(), date(&role.expires)),
    }
}
