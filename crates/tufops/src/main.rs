//! `tufops`: the command line tool signers and publishers use on a checkout of the repository.

mod ui;
mod yubikey;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use clap::{Parser, Subcommand};
use console::style;
use dialoguer::{Confirm, MultiSelect, Password, Select};
use futures_util::io::AllowStdIo;
use tuf::crypto::HashAlgorithm;
use tuf::metadata::{TargetDescription, TargetPath};
use tufops_cloud::{open_signer, open_store, sign_online};
use tufops_core::backend::Signer;
use tufops_core::config::FILE as CONFIG_FILE;
use tufops_core::git::{Git, MAIN, SIGN_PREFIX};
use tufops_core::publish::{publish, target_object};
use tufops_core::repo::METADATA;
use tufops_core::{Config, EventStatus, Repo};
use walkdir::WalkDir;

use crate::yubikey::YubiKeySigner;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// The repository's git checkout.
    #[arg(long, global = true, default_value = ".")]
    repo: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show open signing events and who still has to sign them.
    Status,
    /// Sign open signing events with your YubiKey.
    Sign {
        /// Signing events to sign (without `sign/`); asks when omitted.
        events: Vec<String>,
    },
    /// Upload artifacts and add them to the repository in a signing event.
    Add {
        /// Local file or directory to add.
        #[arg(long)]
        from: PathBuf,
        /// Target path in the repository; a directory when it ends in `/` or `--from` is one.
        #[arg(long)]
        to: String,
        /// Signing event to add to; defaults to one named after `--to`.
        #[arg(long)]
        event: Option<String>,
    },
    /// Update the metadata to match tufops.toml, in a signing event.
    Apply {
        #[arg(long, default_value = "config")]
        event: String,
    },
    /// Start and sign new snapshot and timestamp versions on main if due (normally done by CI).
    Online {
        /// Push the result to the remote main branch.
        #[arg(long)]
        push: bool,
    },
    /// Publish the checked out metadata to storage (normally done by CI).
    Publish,
    /// Print a public key in the form tufops.toml takes.
    Pubkey {
        /// Cloud KMS key URI; reads the YubiKey when omitted.
        #[arg(long)]
        online: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let dir = cli.repo.as_path();
    match cli.command {
        Command::Status => status(dir),
        Command::Sign { events } => sign(dir, events).await,
        Command::Add { from, to, event } => add(dir, &from, &to, event).await,
        Command::Apply { event } => {
            let mut ev = Event::open(dir, &event)?;
            // Uncommitted edits to tufops.toml are what is being applied; the committed config is
            // what the metadata was built from.
            let previous = Config::load_rev(&ev.git, "HEAD").ok();
            ev.head
                .apply_config(&ev.config, previous.as_ref(), &ev.base, Utc::now())?;
            ev.sign_and_finish("Apply tufops.toml", &[METADATA, CONFIG_FILE])
                .await
        }
        Command::Online { push } => {
            let git = Git::new(dir);
            ensure!(git.current_branch()? == MAIN, "check out {MAIN} first");
            let previous = Config::load_rev(&git, "HEAD^").ok();
            let config = Config::load(dir)?;
            let changed = tufops_cloud::update_online(&config, previous.as_ref(), dir).await?;
            if changed.is_empty() {
                println!("Online roles are up to date.");
            } else {
                println!("Signed new versions of {}.", changed.join(", "));
            }
            if git.commit(&format!("Update {}", changed.join(", ")), &[METADATA])? && push {
                git.push(MAIN)?;
                println!("Pushed {MAIN}.");
            }
            Ok(())
        }
        Command::Publish => {
            let store = open_store(&Config::load(dir)?.storage).await?;
            let uploaded = publish(&Repo::load(dir)?, store.as_ref()).await?;
            if uploaded.is_empty() {
                println!("Storage is already up to date.");
            }
            for name in uploaded {
                println!("Uploaded {name}");
            }
            Ok(())
        }
        Command::Pubkey { online } => {
            let key: Box<dyn Signer> = match online {
                Some(uri) => open_signer(&uri).await?,
                None => Box::new(YubiKeySigner::open()?),
            };
            print!("{}", key.public_key().to_pem()?);
            Ok(())
        }
    }
}

/// Shows `err` and asks whether to try again. Never retries when there is no one to ask.
fn try_again(err: &anyhow::Error) -> Result<bool> {
    eprintln!("error: {err:#}");
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    let choice = Select::new()
        .with_prompt("What now?")
        .items(["Try again", "Give up"])
        .default(0)
        .interact()?;
    Ok(choice == 0)
}

fn ask_pin(yubikey: &YubiKeySigner) -> Result<()> {
    yubikey.set_pin(Password::new().with_prompt("YubiKey PIN").interact()?);
    Ok(())
}

/// A signing event checked out in the working tree.
struct Event {
    git: Git,
    branch: String,
    config: Config,
    /// The remote main branch the event will be merged into.
    base: Repo,
    head: Repo,
}

impl Event {
    fn open(dir: &Path, name: &str) -> Result<Self> {
        let git = Git::new(dir);
        let branch = git.checkout_event(name)?;
        let base = Repo::load_rev(&git, &Git::remote_ref(MAIN))?;
        Ok(Self {
            branch,
            config: Config::load(dir)?,
            base,
            head: Repo::load(dir)?,
            git,
        })
    }

    fn roles(&self) -> Vec<String> {
        let roles = self
            .head
            .roles()
            .filter(|r| !matches!(*r, "snapshot" | "timestamp"));
        roles.map(str::to_owned).collect()
    }

    fn status(&self) -> Result<EventStatus> {
        EventStatus::new(&self.config, &self.base, &self.head)
    }

    /// Shows what the YubiKey would sign in this event and, if the user agrees, signs it. A
    /// failed signature (such as a wrong PIN) can be retried; a role given up on is left for
    /// later. Returns whether anything was signed.
    async fn sign_offline(&mut self, yubikey: &YubiKeySigner) -> Result<bool> {
        let me = yubikey.public_key().key_id().clone();
        let status = self.status()?;
        let needed = status.needs(&me);
        if needed.is_empty() {
            return Ok(false);
        }
        println!(
            "\nYour YubiKey ({}, key {}) is needed to sign {} in {}:",
            self.config.describe_key(&me),
            me.as_str().get(..8).unwrap_or_default(),
            if needed.len() == 1 {
                "this role"
            } else {
                "these roles"
            },
            style(&self.branch).bold()
        );
        needed.iter().for_each(|role| ui::print_role(role));
        if !Confirm::new().with_prompt("Sign?").interact()? {
            println!("Not signed.");
            return Ok(false);
        }
        let needed: Vec<_> = needed.iter().map(|r| (r.role.clone(), r.version)).collect();
        if !yubikey.has_pin() {
            ask_pin(yubikey)?;
        }
        let mut signed = false;
        for (role, version) in needed {
            loop {
                println!("Signing {role} version {version}: touch your YubiKey when it blinks.");
                match self.head.sign(&role, yubikey).await {
                    Ok(()) => signed = true,
                    Err(err) if try_again(&err)? => {
                        ask_pin(yubikey)?;
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
    async fn sign_and_finish(mut self, message: &str, paths: &[&str]) -> Result<()> {
        let roles = self.roles();
        while let Err(err) = sign_online(&self.config, &self.base, &mut self.head, &roles).await {
            ensure!(try_again(&err)?, "online signing failed");
        }
        if !self.status()?.complete() {
            match YubiKeySigner::open() {
                Ok(yubikey) => drop(self.sign_offline(&yubikey).await?),
                Err(err) => println!("Not signing with a YubiKey: {err:#}"),
            }
        }
        self.finish(message, paths)
    }

    /// Commits `paths` and pushes the event, then shows its status.
    fn finish(self, message: &str, paths: &[&str]) -> Result<()> {
        self.head.save(self.git.dir())?;
        let committed = self.git.commit(message, paths)?;
        if committed {
            self.git.push(&self.branch)?;
        }
        let status = self.status()?;
        println!();
        ui::print_event(&self.branch, &status);
        println!();
        if committed {
            println!("Pushed {}.", self.branch);
        } else {
            println!("Nothing new to push.");
        }
        let changed_files = self.git.changed_files(&Git::remote_ref(MAIN))?;
        if !status.complete() {
            let waiting: Vec<_> = status.waiting_for().into_iter().collect();
            println!(
                "Waiting for signatures from {}. CI opens a pull request; signers run `tufops sign`.",
                waiting.join(", ")
            );
        } else if status.merges_automatically(&changed_files) {
            println!("All signatures are in: CI merges and publishes it.");
        } else {
            println!("All signatures are in: CI opens a pull request for a maintainer to merge.");
        }
        Ok(())
    }
}

/// Status of every open signing event on the remote.
fn event_statuses(git: &Git) -> Result<Vec<(String, EventStatus)>> {
    git.fetch()?;
    let base = Repo::load_rev(git, &Git::remote_ref(MAIN))?;
    let mut statuses = vec![];
    for event in git.remote_events()? {
        let rev = Git::remote_ref(&format!("{SIGN_PREFIX}{event}"));
        let config = Config::load_rev(git, &rev)?;
        let status = EventStatus::new(&config, &base, &Repo::load_rev(git, &rev)?)?;
        statuses.push((event, status));
    }
    Ok(statuses)
}

fn status(dir: &Path) -> Result<()> {
    let statuses = event_statuses(&Git::new(dir))?;
    if statuses.is_empty() {
        println!("No open signing events.");
    }
    for (event, status) in statuses {
        ui::print_event(&format!("{SIGN_PREFIX}{event}"), &status);
        println!();
    }
    Ok(())
}

async fn sign(dir: &Path, mut events: Vec<String>) -> Result<()> {
    let yubikey = loop {
        match YubiKeySigner::open() {
            Ok(yubikey) => break yubikey,
            Err(err) => ensure!(try_again(&err)?, "no YubiKey"),
        }
    };
    let me = yubikey.public_key().key_id().clone();
    let pending: Vec<_> = event_statuses(&Git::new(dir))?
        .into_iter()
        .filter(|(event, status)| {
            !status.needs(&me).is_empty() && (events.is_empty() || events.contains(event))
        })
        .collect();
    if pending.is_empty() {
        println!("No signing events need your YubiKey (key {me}).");
        return Ok(());
    }
    if events.is_empty() {
        let items: Vec<_> = pending
            .iter()
            .map(|(event, status)| {
                let roles: Vec<_> = status.needs(&me).iter().map(|r| r.role.as_str()).collect();
                format!("{SIGN_PREFIX}{event} (signs {})", roles.join(", "))
            })
            .collect();
        let chosen = MultiSelect::new()
            .with_prompt("Signing events to review (space to toggle)")
            .items(&items)
            .defaults(&vec![true; items.len()])
            .interact()?;
        events = chosen.into_iter().map(|i| pending[i].0.clone()).collect();
    }

    for event in events {
        let mut ev = Event::open(dir, &event)?;
        if ev.sign_offline(&yubikey).await? {
            let message = format!("Sign with {}", ev.config.describe_key(&me));
            ev.finish(&message, &[METADATA])?;
        }
    }
    Ok(())
}

/// Target paths and local files to add: a file goes to `to` (or into it when `to` ends in `/`);
/// a directory's files go under `to`, keeping their relative paths.
fn collect_files(from: &Path, to: &str) -> Result<Vec<(TargetPath, PathBuf)>> {
    if from.is_file() {
        let name = from
            .file_name()
            .and_then(|n| n.to_str())
            .context("bad file name")?;
        let target = if to.ends_with('/') {
            format!("{to}{name}")
        } else {
            to.to_owned()
        };
        return Ok(vec![(TargetPath::new(target)?, from.to_owned())]);
    }
    let mut files = vec![];
    for entry in WalkDir::new(from).sort_by_file_name() {
        let entry = entry?;
        if entry.file_type().is_file() {
            let rel = entry.path().strip_prefix(from)?;
            let parts: Vec<_> = rel
                .iter()
                .map(|c| c.to_str().context("non UTF-8 path"))
                .collect::<Result<_>>()?;
            let target = [to.trim_matches('/'), &parts.join("/")].join("/");
            files.push((
                TargetPath::new(target.trim_start_matches('/'))?,
                entry.into_path(),
            ));
        }
    }
    ensure!(!files.is_empty(), "no files in {from:?}");
    Ok(files)
}

async fn add(dir: &Path, from: &Path, to: &str, event: Option<String>) -> Result<()> {
    let files = collect_files(from, to)?;
    let slug: String = to
        .trim_matches('/')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let mut ev = Event::open(dir, &event.unwrap_or_else(|| format!("add-{slug}")))?;
    let store = open_store(&ev.config.storage).await?;

    let mut targets = vec![];
    for (path, file) in files {
        let reader = AllowStdIo::new(
            std::fs::File::open(&file).with_context(|| format!("opening {file:?}"))?,
        );
        let desc = TargetDescription::from_reader(reader, &[HashAlgorithm::Sha256]).await?;
        let object = target_object(&path, &desc)?;
        println!("Uploading {} as {object}", file.display());
        while let Err(err) = store.put_file(&object, &file).await {
            ensure!(try_again(&err)?, "upload failed");
        }
        targets.push((path, desc));
    }
    let changed = ev
        .head
        .add_targets(&ev.config, &ev.base, targets, Utc::now())?;
    println!("Added to {}", changed.join(", "));
    ev.sign_and_finish(&format!("Add {to}"), &[METADATA]).await
}
