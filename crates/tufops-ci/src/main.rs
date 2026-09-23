//! `tufops-ci`: the automation the tufops GitHub action runs on a checkout of the repository.
//!
//! On a push to a `sign/*` branch it keeps that signing event's pull request up to date and
//! merges the event once it is fully signed. On main (pushes, schedule and manual runs) it signs
//! new snapshot and timestamp versions, publishes, and starts signing events for offline roles
//! about to expire.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::{Parser, Subcommand};
use octocrab::Octocrab;
use octocrab::params::State;
use tufops_cloud::open_store;
use tufops_core::git::{Git, MAIN, REMOTE, SIGN_PREFIX};
use tufops_core::publish::publish;
use tufops_core::repo::METADATA;
use tufops_core::{Config, EventStatus, Repo};

/// Signing event CI starts when offline roles are about to expire.
const REFRESH_EVENT: &str = "refresh";
const FAILURE_TITLE: &str = "tufops automation failed";

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// The repository's git checkout.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Handle the branch in `GITHUB_REF_NAME`: a signing event or main.
    Run,
    /// Open an issue about the failed workflow run, or comment on the one already open.
    ReportFailure,
}

struct GitHub {
    client: Octocrab,
    owner: String,
    repo: String,
}

impl GitHub {
    fn from_env() -> Result<Self> {
        let token = std::env::var("GITHUB_TOKEN").context("GITHUB_TOKEN")?;
        let repository = std::env::var("GITHUB_REPOSITORY").context("GITHUB_REPOSITORY")?;
        let (owner, repo) = repository
            .split_once('/')
            .context("bad GITHUB_REPOSITORY")?;
        let client = Octocrab::builder().personal_token(token).build()?;
        Ok(Self {
            client,
            owner: owner.to_owned(),
            repo: repo.to_owned(),
        })
    }

    /// Updates the description of the open pull request for `branch`, or creates one if `create`.
    async fn update_pr(&self, branch: &str, body: &str, create: bool) -> Result<()> {
        let pulls = self.client.pulls(&self.owner, &self.repo);
        let head = format!("{}:{branch}", self.owner);
        let open = pulls.list().state(State::Open).head(head).send().await?;
        match open.items.first() {
            Some(pr) => drop(pulls.update(pr.number).body(body).send().await?),
            None if create => drop(
                pulls
                    .create(format!("Signing event {branch}"), branch, MAIN)
                    .body(body)
                    .send()
                    .await?,
            ),
            None => {}
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let github = GitHub::from_env()?;
    match cli.command {
        Command::Run => {
            let branch = std::env::var("GITHUB_REF_NAME").context("GITHUB_REF_NAME")?;
            if let Some(event) = branch.strip_prefix(SIGN_PREFIX) {
                signing_event(&github, &cli.repo, event).await
            } else if branch == MAIN {
                main_branch(&cli.repo).await
            } else {
                bail!("tufops runs on {MAIN} and {SIGN_PREFIX}* branches, not {branch}")
            }
        }
        Command::ReportFailure => report_failure(&github).await,
    }
}

/// Merges main into the checked out signing event (without pushing that merge back), so the
/// status reflects what merging the event would publish. Merges into main when every signature
/// is in and only metadata changed; otherwise updates the event's pull request.
async fn signing_event(github: &GitHub, dir: &Path, event: &str) -> Result<()> {
    let git = Git::new(dir);
    let branch = format!("{SIGN_PREFIX}{event}");
    let main = Git::remote_ref(MAIN);
    let tip = git.run(&["rev-parse", "HEAD"])?;
    // Another run may move main between our merge and push; then merge again.
    for attempt in 1.. {
        git.fetch()?;
        git.run(&["checkout", "--quiet", "-B", &branch, &tip])?;
        git.run(&["merge", "--no-edit", &main]).with_context(|| {
            format!("{branch} conflicts with {MAIN}; start it again from {MAIN}")
        })?;
        let changed_files = git.run(&["diff", "--name-only", &main, "HEAD"])?;
        if changed_files.is_empty() {
            println!("{branch} changes nothing");
            return Ok(());
        }
        let config = Config::load(dir)?;
        let status = EventStatus::new(&Repo::load_rev(&git, &main)?, &Repo::load(dir)?)?;
        let only_metadata = changed_files
            .lines()
            .all(|f| f.starts_with(&format!("{METADATA}/")));

        let mut body = format!(
            "## Signing event `{branch}`\n\n{}\n",
            status.to_markdown(&config)
        );
        body.push_str(match (status.complete(), only_metadata) {
            (false, _) => "Signers still needed: check out the repository and run `tufops sign`.",
            (true, true) => "All signatures are in: merging.",
            (true, false) => {
                "All signatures are in. This event changes more than metadata, so a maintainer \
                 must review and merge it."
            }
        });
        println!("{body}");
        // Events that merge straight away, such as those only online keys sign, need no pull
        // request.
        let merge = status.complete() && only_metadata;
        github.update_pr(&branch, &body, !merge).await?;
        if !merge {
            return Ok(());
        }
        match git.run(&["push", REMOTE, &format!("HEAD:refs/heads/{MAIN}")]) {
            Ok(_) => return git.run(&["push", REMOTE, "--delete", &branch]).map(drop),
            Err(err) if attempt < 3 => eprintln!("retrying: {err:#}"),
            Err(err) => return Err(err),
        }
    }
    unreachable!()
}

/// Signs new online role versions that are due, publishes, and starts a signing event for
/// offline roles in their signing period.
async fn main_branch(dir: &Path) -> Result<()> {
    let git = Git::new(dir);
    let config = Config::load(dir)?;
    let changed = tufops_cloud::update_online(&config, dir).await?;
    if git.commit_all(&format!("Update {}", changed.join(", ")))?
        && let Err(err) = git.push(MAIN)
    {
        // If main moved on, the run for the newer commit does this work instead.
        git.fetch()?;
        if git.run(&["rev-parse", "HEAD~1"])? != git.run(&["rev-parse", &Git::remote_ref(MAIN)])? {
            println!("{MAIN} moved on ({err:#}); leaving the work to the newer run");
            return Ok(());
        }
        return Err(err);
    }

    let repo = Repo::load(dir)?;
    let store = open_store(&config.storage).await?;
    let uploaded = publish(&repo, store.as_ref()).await?;
    println!("Published {} objects: {uploaded:?}", uploaded.len());

    git.fetch()?;
    if git.remote_events()?.iter().any(|e| e == REFRESH_EVENT) {
        return Ok(());
    }
    let mut head = repo.clone();
    let expiring = head.apply_config(&config, &repo, Utc::now())?;
    if !expiring.is_empty() {
        let branch = git.checkout_event(REFRESH_EVENT)?;
        head.save(dir)?;
        git.commit_all(&format!("Start new versions of {}", expiring.join(", ")))?;
        git.push(&branch)?;
        println!("Started {branch} for {expiring:?}; its workflow run opens the pull request");
    }
    Ok(())
}

async fn report_failure(github: &GitHub) -> Result<()> {
    let var = |name| std::env::var(name).unwrap_or_default();
    let run = format!(
        "{}/{}/actions/runs/{}",
        var("GITHUB_SERVER_URL"),
        var("GITHUB_REPOSITORY"),
        var("GITHUB_RUN_ID")
    );
    let body = format!("tufops failed on `{}`: {run}", var("GITHUB_REF_NAME"));
    let issues = github.client.issues(&github.owner, &github.repo);
    let open = issues
        .list()
        .state(State::Open)
        .per_page(100u8)
        .send()
        .await?;
    match open
        .items
        .iter()
        .find(|i| i.title == FAILURE_TITLE && i.pull_request.is_none())
    {
        Some(issue) => drop(issues.create_comment(issue.number, body).await?),
        None => drop(issues.create(FAILURE_TITLE).body(body).send().await?),
    }
    Ok(())
}
