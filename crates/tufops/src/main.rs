//! `tufops`: the command line tool signers and publishers use on a checkout of the repository.

mod add;
mod event;
mod ui;
mod yubikey;

use std::io::{IsTerminal, stdout};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use clap::{Parser, Subcommand};
use dialoguer::{MultiSelect, Select};
use tracing::debug;
use tracing_subscriber::EnvFilter;
use tuf::metadata::TargetPath;
use tufops_cloud::{open_signer, open_store};
use tufops_core::backend::Signer;
use tufops_core::config::FILE as CONFIG_FILE;
use tufops_core::git::{Git, MAIN, SIGN_PREFIX};
use tufops_core::publish::publish;
use tufops_core::repo::{METADATA, covers};
use tufops_core::{Config, EventStatus, Repo};

use crate::event::{Event, slug, started_from};
use crate::yubikey::YubiKeySigner;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// The repository's git checkout.
    #[arg(long, global = true, default_value = ".")]
    repo: PathBuf,
    /// Serial number of the YubiKey to use, when several are plugged in.
    #[arg(long, global = true)]
    device: Option<u32>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show open signing events and who still has to sign them.
    Status,
    /// Sign open signing events with your YubiKey.
    Sign {
        /// Signing events to sign (without `sign/`); asks when omitted.
        events: Vec<String>,
    },
    /// Upload new and changed artifacts and add them to the repository in a new signing event.
    Add {
        /// Local file or directory to add.
        #[arg(long)]
        from: PathBuf,
        /// Target path in the repository; a directory when it ends in `/` or `--from` is one.
        #[arg(long)]
        to: String,
        /// Also remove the targets in the `--to` directory that `--from` lacks, so it matches
        /// `--from` exactly; their uploads are kept.
        #[arg(long)]
        delete: bool,
        /// List what would be added, changed and removed, without uploading, signing or pushing
        /// anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove artifacts from the repository in a new signing event; their uploads are kept.
    Rm {
        /// Target paths to remove; a path ending in `/` removes everything under it.
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Update the metadata to match your edits to tufops.toml, in a new signing event.
    Apply,
    /// Start, sign and push new snapshot and timestamp versions on main if due (normally done by
    /// CI).
    Online,
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
    init_tracing()?;
    debug!(?cli, "tufops {}", env!("CARGO_PKG_VERSION"));
    let dir = cli.repo.as_path();
    let device = cli.device;
    // Changes start from main as everyone sees it, and are made in temporary worktrees, so the
    // checkout itself stays as it is.
    if !matches!(cli.command, Command::Pubkey { .. }) {
        Git::new(dir).check_main()?;
    }
    match cli.command {
        Command::Status => status(dir),
        Command::Sign { events } => sign(dir, events, device).await,
        Command::Add {
            from,
            to,
            delete,
            dry_run,
        } => add::add(dir, &from, &to, delete, dry_run, device).await,
        Command::Rm { paths } => rm(dir, &paths, device).await,
        Command::Apply => {
            // The checkout's edits to tufops.toml are what is being applied; main's config is
            // what the metadata was built from.
            let config = Config::load(dir)?;
            let mut ev = Event::start(dir, "config")?;
            std::fs::copy(dir.join(CONFIG_FILE), ev.worktree.dir().join(CONFIG_FILE))?;
            ev.head
                .apply_config(&config, Some(&ev.config), &ev.base, Utc::now())?;
            ev.config = config;
            ev.sign_and_finish("Apply tufops.toml", &[METADATA, CONFIG_FILE], device)
                .await
        }
        Command::Online => {
            let worktree = Git::new(dir).worktree(&Git::remote_ref(MAIN))?;
            let previous = Config::load_rev(&worktree, "HEAD^")
                .inspect_err(|err| debug!("no previous config: {err:#}"))
                .ok();
            let config = Config::load(worktree.dir())?;
            let changed =
                tufops_cloud::update_online(&worktree, &config, previous.as_ref()).await?;
            if changed.is_empty() {
                println!("Online roles are up to date.");
                return Ok(());
            }
            worktree.push(MAIN)?;
            println!(
                "Signed new versions of {} and pushed {MAIN}.",
                changed.join(", ")
            );
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
                None => Box::new(YubiKeySigner::open(device)?),
            };
            print!("{}", key.public_key().to_pem()?);
            Ok(())
        }
    }
}

/// Logs to stderr when `TUFOPS_LOG` is set, filtered by its directives (such as `tufops=debug`).
fn init_tracing() -> Result<()> {
    let directives = std::env::var("TUFOPS_LOG").unwrap_or_default();
    if directives.is_empty() {
        return Ok(());
    }
    let filter = EnvFilter::try_new(&directives).context("invalid TUFOPS_LOG")?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    Ok(())
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

/// Status of every open signing event on the remote.
fn event_statuses(git: &Git) -> Result<Vec<(String, EventStatus)>> {
    let mut statuses = vec![];
    for event in git.remote_events()? {
        let rev = Git::remote_ref(&format!("{SIGN_PREFIX}{event}"));
        let config = Config::load_rev(git, &rev)?;
        let base = started_from(git, &rev)?;
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
        ui::write_event(&mut stdout(), &format!("{SIGN_PREFIX}{event}"), &status);
        println!();
    }
    Ok(())
}

async fn sign(dir: &Path, mut events: Vec<String>, device: Option<u32>) -> Result<()> {
    let yubikey = loop {
        match YubiKeySigner::open(device) {
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

async fn rm(dir: &Path, paths: &[String], device: Option<u32>) -> Result<()> {
    let patterns: Vec<_> = paths
        .iter()
        .map(|p| TargetPath::new(p.clone()).with_context(|| format!("target path {p}")))
        .collect::<Result<_>>()?;
    let mut ev = Event::start(dir, &format!("rm-{}", slug(&paths[0])))?;
    // A path ending in `/` also matches everything under it, like delegation paths.
    let matches = |path: &TargetPath| patterns.iter().any(|p| covers(p, path));
    let (changed, removed) = ev
        .head
        .remove_targets(&ev.config, &ev.base, matches, Utc::now())?;
    ensure!(removed > 0, "no targets match {}", paths.join(", "));
    println!("Removing {removed} targets from {}", changed.join(", "));
    ev.sign_and_finish(&format!("Remove {}", paths.join(", ")), &[METADATA], device)
        .await
}
