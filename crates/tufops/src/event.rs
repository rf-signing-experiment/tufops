//! Signing events: checking one out, signing it with online keys and the YubiKey, and pushing it.

use std::io::stdout;
use std::path::Path;

use anyhow::{Result, ensure};
use clap::Args;
use console::style;
use dialoguer::Confirm;
use tufops_cloud::sign_online;
use tufops_core::backend::Signer;
use tufops_core::git::{Git, MAIN};
use tufops_core::status::short;
use tufops_core::{Config, EventStatus, Repo};

use crate::try_again;
use crate::ui;
use crate::yubikey::YubiKeySigner;

/// The signing event a command makes its change in.
#[derive(Args, Debug)]
pub struct EventArgs {
    /// Signing event to make the change in (without `sign/`); defaults to one named after the
    /// change.
    #[arg(long)]
    event: Option<String>,
    /// Start the event over from main, discarding its earlier changes and signatures.
    #[arg(long)]
    restart: bool,
}

impl EventArgs {
    /// Checks out the event, named `default` unless `--event` names one.
    pub fn open(&self, dir: &Path, default: &str) -> Result<Event> {
        Event::open(dir, self.event.as_deref().unwrap_or(default), self.restart)
    }

    /// The metadata `open` would start from, without checking anything out.
    pub fn preview(&self, dir: &Path, default: &str) -> Result<Repo> {
        let git = Git::new(dir);
        let event = self.event.as_deref().unwrap_or(default);
        Repo::load_rev(&git, &git.preview_event(event, self.restart)?)
    }
}

/// A signing event checked out in the working tree.
pub struct Event {
    pub git: Git,
    branch: String,
    pub config: Config,
    /// The remote main branch the event will be merged into.
    pub base: Repo,
    pub head: Repo,
    /// Whether the event started over, so pushing it replaces the remote branch.
    pub restart: bool,
}

impl Event {
    pub fn open(dir: &Path, name: &str, restart: bool) -> Result<Self> {
        let git = Git::new(dir);
        let branch = git.checkout_event(name, restart)?;
        if restart {
            println!("Starting {branch} over from {MAIN}.");
        }
        Ok(Self {
            base: Repo::load_rev(&git, &Git::remote_ref(MAIN))?,
            config: Config::load(dir)?,
            head: Repo::load(dir)?,
            branch,
            git,
            restart,
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
        self.head.save(self.git.dir())?;
        let committed = self.git.commit(message, paths)?;
        if committed || self.restart {
            self.git.push(&self.branch, self.restart)?;
        }
        let status = self.status()?;
        println!();
        ui::write_event(&mut stdout(), &self.branch, &status);
        println!();
        if self.restart {
            println!("Pushed {}, replacing the earlier event.", self.branch);
        } else if committed {
            println!("Pushed {}.", self.branch);
        } else {
            println!("Nothing new to push.");
        }
        let changed_files = self.git.changed_files(&Git::remote_ref(MAIN))?;
        println!("{}", status.next_step(&changed_files));
        Ok(())
    }
}

/// `path` as part of a branch name.
pub fn slug(path: &str) -> String {
    let keep = |c: char| c.is_ascii_alphanumeric() || c == '.';
    let chars = path.trim_matches('/').chars();
    chars.map(|c| if keep(c) { c } else { '-' }).collect()
}
