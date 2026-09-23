//! `tufops`: the command line tool signers and publishers use on a checkout of the repository.

mod yubikey;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use clap::{Parser, Subcommand};
use dialoguer::{Confirm, MultiSelect, Password, Select};
use futures_util::io::AllowStdIo;
use tuf::crypto::HashAlgorithm;
use tuf::metadata::{TargetDescription, TargetPath};
use tufops_cloud::{open_signer, open_store, sign_online};
use tufops_core::backend::Signer;
use tufops_core::git::{Git, MAIN, SIGN_PREFIX};
use tufops_core::publish::{publish, target_object};
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
            ev.head.apply_config(&ev.config, &ev.base, Utc::now())?;
            ev.sign_and_finish("Apply tufops.toml").await
        }
        Command::Online { push } => {
            let git = Git::new(dir);
            ensure!(git.current_branch()? == MAIN, "check out {MAIN} first");
            let changed = tufops_cloud::update_online(&Config::load(dir)?, dir).await?;
            if git.commit_all(&format!("Update {}", changed.join(", ")))? && push {
                git.push(MAIN)?;
            }
            println!("Updated: {changed:?}");
            Ok(())
        }
        Command::Publish => {
            let store = open_store(&Config::load(dir)?.storage).await?;
            let uploaded = publish(&Repo::load(dir)?, store.as_ref()).await?;
            println!("Uploaded: {uploaded:?}");
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
        self.head
            .roles()
            .filter(|r| !matches!(*r, "snapshot" | "timestamp"))
            .map(str::to_owned)
            .collect()
    }

    /// Signs every role that needs the YubiKey's key. A failed signature (such as a wrong PIN)
    /// can be retried; a role given up on is left for later.
    async fn sign_offline(&mut self, yubikey: &YubiKeySigner) -> Result<()> {
        for role in self.roles() {
            if !self
                .head
                .missing_keys(&self.base, &role)?
                .contains(yubikey.public_key())
            {
                continue;
            }
            println!("Signing {role}");
            while let Err(err) = self.head.sign(&role, yubikey).await {
                if !try_again(&err)? {
                    eprintln!("Skipped {role}");
                    break;
                }
                ask_pin(yubikey)?;
            }
        }
        Ok(())
    }

    /// Signs with the online keys the event needs, and with the YubiKey if one is plugged in and
    /// needed, then commits and pushes the event.
    async fn sign_and_finish(mut self, message: &str) -> Result<()> {
        let roles = self.roles();
        while let Err(err) = sign_online(&self.config, &self.base, &mut self.head, &roles).await {
            ensure!(try_again(&err)?, "online signing failed");
        }
        let status = EventStatus::new(&self.base, &self.head)?;
        if !status.complete() {
            match YubiKeySigner::open() {
                Ok(yubikey) if !status.needs(yubikey.public_key().key_id()).is_empty() => {
                    ask_pin(&yubikey)?;
                    self.sign_offline(&yubikey).await?;
                }
                Ok(_) => {}
                Err(err) => println!("Not signing with a YubiKey: {err:#}"),
            }
        }
        self.finish(message)
    }

    fn finish(self, message: &str) -> Result<()> {
        self.head.save(self.git.dir())?;
        if self.git.commit_all(message)? {
            self.git.push(&self.branch)?;
            println!("Pushed {}.", self.branch);
        } else {
            println!("Nothing changed in {}.", self.branch);
        }
        let status = EventStatus::new(&self.base, &self.head)?;
        println!("\n{}", status.to_markdown(&self.config));
        if status.complete() {
            println!("All signatures are in: CI will merge {}.", self.branch);
        } else {
            println!(
                "CI will open a pull request; the signers listed can sign with `tufops sign`."
            );
        }
        Ok(())
    }
}

/// Status of every open signing event on the remote.
fn event_statuses(git: &Git) -> Result<Vec<(String, Config, EventStatus)>> {
    git.fetch()?;
    let base = Repo::load_rev(git, &Git::remote_ref(MAIN))?;
    let mut statuses = vec![];
    for event in git.remote_events()? {
        let rev = Git::remote_ref(&format!("{SIGN_PREFIX}{event}"));
        let status = EventStatus::new(&base, &Repo::load_rev(git, &rev)?)?;
        statuses.push((event, Config::load_rev(git, &rev)?, status));
    }
    Ok(statuses)
}

fn status(dir: &Path) -> Result<()> {
    let statuses = event_statuses(&Git::new(dir))?;
    if statuses.is_empty() {
        println!("No open signing events.");
    }
    for (event, config, status) in statuses {
        println!("## {SIGN_PREFIX}{event}\n\n{}", status.to_markdown(&config));
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
        .filter(|(event, _, status)| {
            !status.needs(&me).is_empty() && (events.is_empty() || events.contains(event))
        })
        .collect();
    if pending.is_empty() {
        println!("No signing events need your key ({me}).");
        return Ok(());
    }
    if events.is_empty() {
        let items: Vec<_> = pending
            .iter()
            .map(|(event, _, status)| format!("{event} (signs {:?})", status.needs(&me)))
            .collect();
        let chosen = MultiSelect::new()
            .with_prompt("Signing events to sign (space to toggle)")
            .items(&items)
            .defaults(&vec![true; items.len()])
            .interact()?;
        events = chosen.into_iter().map(|i| pending[i].0.clone()).collect();
    }

    ask_pin(&yubikey)?;
    for event in events {
        let mut ev = Event::open(dir, &event)?;
        println!(
            "\n## {}\n\n{}",
            ev.branch,
            EventStatus::new(&ev.base, &ev.head)?.to_markdown(&ev.config)
        );
        if Confirm::new()
            .with_prompt(format!("Sign {}?", ev.branch))
            .default(true)
            .interact()?
        {
            ev.sign_offline(&yubikey).await?;
            let message = format!("Sign with {}", ev.config.describe_key(&me));
            ev.finish(&message)?;
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
    ev.sign_and_finish(&format!("Add {to}")).await
}
