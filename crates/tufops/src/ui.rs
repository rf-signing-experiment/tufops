//! The signing status as plain text for the terminal. `tufops-ci` renders the same status as
//! markdown for pull requests in `markdown.rs`, with matching functions: change the two together.

use std::io::Write;

use chrono::{DateTime, Utc};
use console::style;
use tufops_core::EventStatus;
use tufops_core::status::{Key, Requirement, RoleStatus};

/// Writes what a signing event changes and who has signed it: each role's changes, followed by
/// its requirements.
pub fn write_event(out: &mut impl Write, branch: &str, status: &EventStatus) {
    let _ = writeln!(out, "{}", style(branch).bold());
    if status.roles.is_empty() {
        let _ = writeln!(out, "  nothing to sign");
    }
    for role in &status.roles {
        write_role(out, role);
        role.requirements
            .iter()
            .for_each(|req| write_requirement(out, req));
    }
}

/// Writes a role's version and expiry, and every change to its metadata.
pub fn write_role(out: &mut impl Write, role: &RoleStatus) {
    let _ = writeln!(out, "  {}  {}", style(&role.role).bold(), version(role));
    if role.changes.is_empty() && role.base.is_some_and(|(v, _)| v != role.version) {
        let _ = writeln!(out, "    no changes besides version and expiry");
    }
    for change in &role.changes {
        let _ = writeln!(out, "    {change}");
    }
}

/// Writes whether a requirement is met, who signed it, and who it still waits for.
fn write_requirement(out: &mut impl Write, req: &Requirement) {
    let mark = if req.met() {
        style("✓").green()
    } else {
        style("✗").yellow()
    };
    let label = if req.previous_root {
        "signatures from the previous root keys"
    } else {
        "signatures"
    };
    let mut line = format!(
        "    {mark} {label}: {} of {}",
        req.signed.len(),
        req.threshold
    );
    if !req.signed.is_empty() {
        line += &format!(", signed by {}", names(&req.signed));
    }
    if !req.met() {
        line += &format!(", waiting for {}", names(req.awaited()));
    }
    let _ = writeln!(out, "{line}");
}

/// The version and expiry: what main has, and what the event changes them to.
fn version(role: &RoleStatus) -> String {
    let date = |d: &DateTime<Utc>| d.format("%Y-%m-%d %H:%M UTC").to_string();
    match role.base {
        None => format!(
            "new, version {}, expires {}",
            role.version,
            date(&role.expires)
        ),
        Some((version, expires)) if version != role.version => format!(
            "version {version} → {}, expires {} (was {})",
            role.version,
            date(&role.expires),
            date(&expires)
        ),
        Some(_) => format!("version {}, expires {}", role.version, date(&role.expires)),
    }
}

fn names(keys: &[Key]) -> String {
    let names: Vec<_> = keys.iter().map(|k| k.name.as_str()).collect();
    names.join(", ")
}
