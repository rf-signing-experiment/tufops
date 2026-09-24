//! Plain text output for the terminal.

use chrono::{DateTime, Utc};
use console::style;
use tufops_core::EventStatus;
use tufops_core::status::{Key, Requirement, RoleStatus};

/// Prints what a signing event changes and who has signed it.
pub fn print_event(branch: &str, status: &EventStatus) {
    println!("{}", style(branch).bold());
    if status.roles.is_empty() {
        println!("  nothing to sign");
    }
    for role in &status.roles {
        print_role(role);
        role.requirements.iter().for_each(print_requirement);
    }
}

/// Prints a role's new version and every change to its metadata.
pub fn print_role(role: &RoleStatus) {
    let date = |d: &DateTime<Utc>| d.format("%Y-%m-%d %H:%M UTC").to_string();
    let header = match role.base {
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
    };
    println!("  {}  {header}", style(&role.role).bold());
    if role.changes.is_empty() && role.base.is_some_and(|(v, _)| v != role.version) {
        println!("    no changes besides version and expiry");
    }
    for change in &role.changes {
        println!("    {change}");
    }
}

fn print_requirement(req: &Requirement) {
    let names = |keys: &[Key]| {
        keys.iter()
            .map(|k| k.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
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
        line += &format!(", waiting for {}", names(&req.unsigned));
    }
    println!("{line}");
}
