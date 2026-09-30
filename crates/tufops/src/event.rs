//! Signing events: making or signing one in a temporary worktree, so the user's checkout stays on
//! main, signing it with online keys and the YubiKey, and pushing it.

use std::io::stdout;
use std::path::Path;

use anyhow::{Result, ensure};
use chrono::Utc;
use console::style;
use dialoguer::Confirm;
use tufops_cloud::sign_online;
use tufops_core::backend::Signer;
use tufops_core::git::{Git, MAIN, SIGN_PREFIX, Worktree};
use tufops_core::status::short;
use tufops_core::{Config, EventStatus, Repo};

use crate::try_again;
use crate::ui;
use crate::yubikey::YubiKeySigner;

/// A signing event checked out in a temporary worktree.
pub struct Event {
    pub worktree: Worktree,
    branch: String,
    pub config: Config,
    /// The main commit the event started from.
    pub base: Repo,
    pub head: Repo,
}

impl Event {
    /// Starts a new event from main, named after `kind` and the time so the name is new.
    pub fn start(dir: &Path, kind: &str) -> Result<Self> {
        let name = format!("{kind}-{}", Utc::now().format("%Y%m%d-%H%M%S"));
        Self::checkout(dir, &name, &Git::remote_ref(MAIN))
    }

    /// Opens the event `name` as the remote has it.
    pub fn open(dir: &Path, name: &str) -> Result<Self> {
        Self::checkout(dir, name, &Git::remote_ref(&format!("{SIGN_PREFIX}{name}")))
    }

    fn checkout(dir: &Path, name: &str, rev: &str) -> Result<Self> {
        let git = Git::new(dir);
        let worktree = git.worktree(rev)?;
        Ok(Self {
            base: started_from(&git, rev)?,
            config: Config::load(worktree.dir())?,
            head: Repo::load(worktree.dir())?,
            branch: format!("{SIGN_PREFIX}{name}"),
            worktree,
        })
    }

    fn status(&self) -> Result<EventStatus> {
        EventStatus::new(&self.config, &self.base, &self.head)
    }

    /// Shows what the YubiKey would sign in this event and, if the user agrees, signs it. A
    /// failed signature (such as a wrong PIN) can be retried; a role given up on is left for
    /// later. Returns whether anything was signed.
    pub async fn sign_offline(&mut self, yubikey: &YubiKeySigner) -> Result<bool> {
        let me = yubikey.public_key().key_id().clone();
        let status = self.status()?;
        let needed = status.needs(&me);
        if needed.is_empty() {
            return Ok(false);
        }
        println!(
            "\nYour YubiKey ({}, key {}) is needed to sign {} in {}:",
            self.config.describe_key(&me),
            short(&me),
            if needed.len() == 1 {
                "this role"
            } else {
                "these roles"
            },
            style(&self.branch).bold()
        );
        needed.iter().for_each(|r| ui::write_role(&mut stdout(), r));
        if !Confirm::new().with_prompt("Sign?").interact()? {
            println!("Not signed.");
            return Ok(false);
        }
        let needed: Vec<_> = needed.iter().map(|r| (r.role.clone(), r.version)).collect();
        if !yubikey.has_pin() {
            yubikey.ask_pin()?;
        }
        let mut signed = false;
        for (role, version) in needed {
            loop {
                println!("Signing {role} version {version}: touch your YubiKey if needed.");
                match self.head.sign(&role, yubikey).await {
                    Ok(()) => signed = true,
                    Err(err) if try_again(&err)? => {
                        yubikey.ask_pin()?;
                        continue;
                    }
                    Err(_) => println!("Skipped {role}."),
                }
                break;
            }
        }
        Ok(signed)
    }

    /// Signs with the online keys the event needs, and with the YubiKey if one is plugged in and
    /// needed, then commits and pushes the event.
    pub async fn sign_and_finish(
        mut self,
        message: &str,
        paths: &[&str],
        device: Option<u32>,
    ) -> Result<()> {
        let roles = self.head.event_roles();
        while let Err(err) = sign_online(&self.config, &self.base, &mut self.head, &roles).await {
            ensure!(try_again(&err)?, "online signing failed");
        }
        if !self.status()?.complete() {
            match YubiKeySigner::open(device) {
                Ok(yubikey) => drop(self.sign_offline(&yubikey).await?),
                Err(err) => println!("Not signing with a YubiKey: {err:#}"),
            }
        }
        self.finish(message, paths)
    }

    /// Commits `paths` and pushes the event, then shows its status.
    pub fn finish(self, message: &str, paths: &[&str]) -> Result<()> {
        self.head.save(self.worktree.dir())?;
        if !self.worktree.commit(message, paths)? {
            println!("Nothing new to push.");
            return Ok(());
        }
        self.worktree.push(&self.branch)?;
        let status = self.status()?;
        println!();
        ui::write_event(&mut stdout(), &self.branch, &status);
        println!();
        println!("Pushed {}.", self.branch);
        let changed_files = self.worktree.changed_files(&Git::remote_ref(MAIN))?;
        println!("{}", status.next_step(&changed_files));
        Ok(())
    }
}

/// The metadata of the main commit that the event at `rev` started from. Comparing an event with
/// that, rather than with main, keeps what was merged into main since out of its changes.
pub fn started_from(git: &Git, rev: &str) -> Result<Repo> {
    Repo::load_rev(git, &git.merge_base(&Git::remote_ref(MAIN), rev)?)
}

/// `path` as part of a branch name.
pub fn slug(path: &str) -> String {
    let keep = |c: char| c.is_ascii_alphanumeric() || c == '.';
    let chars = path.trim_matches('/').chars();
    chars.map(|c| if keep(c) { c } else { '-' }).collect()
}
